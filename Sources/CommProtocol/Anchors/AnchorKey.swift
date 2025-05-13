//
//  AnchorKey.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 3/6/25.
//

import CryptoKit
import Foundation

//taking an approach different from Identity and Agent where we make the
//Private and Public Agent encapsulate more of the associated data
//instead of being just a typed wrapper on

public struct AnchorPrivateKey: Sendable {
	private let privateKey: any PrivateSigningKey
	public let publicKey: AnchorPublicKey

	var type: SigningKeyAlgorithm {
		Swift.type(of: privateKey).signingAlgorithm
	}

	//for local storage
	public var archive: TypedKeyMaterial { .init(typedKey: privateKey) }

	init(archive: TypedKeyMaterial) throws {
		switch archive.algorithm {
		case .curve25519Signing:
			self.init(
				concrete: try Curve25519.Signing.PrivateKey(
					rawRepresentation: archive.keyData)
			)
		default: throw ProtocolError.typedKeyArchiveMismatch
		}
	}

	private init(concrete: any PrivateSigningKey) {
		privateKey = concrete
		publicKey = .init(concrete: concrete.publicKey)
	}

	init(algorithm: SigningKeyAlgorithm = .curve25519) {
		switch algorithm {
		case .curve25519:
			self.privateKey = Curve25519.Signing.PrivateKey()
			self.publicKey = .init(concrete: privateKey.publicKey)
		}
	}

	var signer: @Sendable (Data) throws -> TypedSignature {
		{ body in
			try .init(
				signingAlgorithm: type,
				signature: privateKey.signature(for: body)
			)

		}
	}

	public func sign(over body: Data) throws -> TypedSignature {
		.init(
			signingAlgorithm: type,
			signature: try privateKey.signature(for: body)
		)
	}
}

public struct AnchorPublicKey: Sendable {
	let publicKey: any PublicSigningKey
	let archive: TypedKeyMaterial

	var type: SigningKeyAlgorithm { Swift.type(of: publicKey).signingAlgorithm }
	public var wireFormat: Data { archive.wireFormat }

	init(concrete: any PublicSigningKey) {
		publicKey = concrete
		archive = .init(typedKey: publicKey)
	}

	public init(wireFormat: Data) throws {
		try self.init(archive: .init(wireFormat: wireFormat))
	}

	public init(archive: TypedKeyMaterial) throws {
		switch archive.algorithm {
		case .curve25519Signing:
			self.init(
				concrete: try Curve25519.Signing
					.PublicKey(rawRepresentation: archive.keyData)
			)
		default:
			throw ProtocolError.typedKeyArchiveMismatch
		}
	}

	//signature, data
	var verifier: @Sendable (TypedSignature, Data) -> Bool {
		{ signature, body in
			guard signature.signingAlgorithm == type else {
				return false
			}
			return publicKey.isValidSignature(signature.signature, for: body)
		}
	}
}

extension AnchorPublicKey {
	//did/AnchorTo should be known as we needed it to fetch this
	public func verify(
		hello: AnchorHello,
		for destination: AnchorAttestation
	) throws -> AnchorHello.Verified {

		let verifiedPackage = try verifyPackage(hello: hello)
		let newAgentKey = try AgentPublicKey(
			archive: verifiedPackage.first.fourth.first
		)

		guard
			newAgentKey.verifier(
				verifiedPackage.second,
				try verifiedPackage.first.agentSignatureBody().wireFormat
			)
		else {
			throw ProtocolError.authenticationError
		}
		let content = verifiedPackage.first

		let publicAnchor = PublicAnchor(
			publicKey: self,
			attestation: content.first
		)
		guard content.first.archive == destination.archive else {
			throw ProtocolError.authenticationError
		}

		return .init(
			agent: .init(
				anchor: publicAnchor,
				agentKey: newAgentKey
			),
			succession: try publicAnchor.verify(proofs: content.second),
			policy: content.third,
			version: content.fourth.second,
			mlsKeyPackages: content.fourth.third,
		)
	}

	private func verifyPackage(hello: AnchorHello) throws -> AnchorHello.Package {
		guard
			verifier(
				hello.first,
				try AnchorHello.AnchorSignatureBody(
					encodedPackage: hello.second,
					knownAnchor: self
				).wireFormat
			)
		else {
			throw ProtocolError.authenticationError
		}

		return try .finalParse(hello.second)
	}
}

extension AnchorPublicKey {
	public func verify(
		reply: AnchorReply,
		mlsWelcomeDigest: TypedDigest,
		recipient: PublicAnchor,
		mlsGroupId: Data,
	) throws -> AnchorReply.Verified {
		let verifiedPackage = try verify(
			reply: reply,
			recipient: recipient,
			mlsGroupId: mlsGroupId
		)
		let newAgentKey = try AgentPublicKey(
			archive: verifiedPackage.first.second
		)

		let agentSignatureBody = try verifiedPackage.first
			.agentSignatureBody(
				mlsWelcomeDigest: mlsWelcomeDigest,
				recipient: recipient,
				mlsGroupId: mlsGroupId
			)
			.wireFormat

		guard
			newAgentKey.verifier(
				verifiedPackage.second,
				agentSignatureBody
			)
		else {
			throw ProtocolError.authenticationError
		}
		let content = verifiedPackage.first

		return .init(
			agent: .init(
				anchor: .init(
					publicKey: self,
					attestation: content.first
				),
				agentKey: newAgentKey
			),
			welcome: content.third
		)
	}

	private func verify(
		reply: AnchorReply,
		recipient: PublicAnchor,
		mlsGroupId: Data,
	) throws -> AnchorReply.Package {
		guard
			verifier(
				reply.first,
				try AnchorReply.AnchorSignatureBody(
					encodedPackage: reply.second,
					knownAnchor: self,
					recipient: recipient,
					mlsGroupId: mlsGroupId
				).wireFormat
			)
		else {
			throw ProtocolError.authenticationError
		}

		return try .finalParse(reply.second)
	}
}

extension PublicAnchor {
	//is this a chain of proofs that terminates with me?
	//return the verified chain and let the caller match with known predecessor
	func verify(proofs: [AnchorSuccession.Proof]) throws -> [AnchorPublicKey] {
		var tailKey = self.publicKey
		var result: [AnchorPublicKey] = []

		for proof in proofs.reversed() {
			let previousKey = try tailKey.verify(
				successionFrom: proof,
				attestation: attestation
			)
			result = [previousKey] + result
			tailKey = previousKey
		}
		return result
	}
}

extension AnchorPublicKey {
	//returns the previous key
	func verify(
		successionFrom: AnchorSuccession.Proof,
		attestation: AnchorAttestation
	) throws -> AnchorPublicKey {
		let predecessor = try AnchorPublicKey(archive: successionFrom.predecessor)
		let result = verifier(
			successionFrom.signature,
			try AnchorSuccession.signatureBody(
				attestation: attestation,
				predecessor: predecessor,
				successor: self,

			)
		)
		guard result else { throw ProtocolError.authenticationError }
		return predecessor
	}
}

extension AnchorPublicKey: Equatable {
	public static func == (lhs: AnchorPublicKey, rhs: AnchorPublicKey) -> Bool {
		lhs.wireFormat == rhs.wireFormat
	}
}

extension AnchorPublicKey: Hashable {
	//MARK: Hashable
	public func hash(into hasher: inout Hasher) {
		hasher.combine("Anchor Public Key")
		hasher.combine(archive)
	}
}
