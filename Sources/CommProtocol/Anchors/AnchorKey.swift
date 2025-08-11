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

	public init(archive: TypedKeyMaterial) throws {
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

	public var signer: @Sendable (Data) throws -> TypedSignature {
		{ body in
			try .init(
				signingAlgorithm: type,
				signature: privateKey.signature(for: body)
			)

		}
	}

	public func sign(
		mutableData: IdentityMutableData
	) throws -> SignedObject<IdentityMutableData> {
		.init(
			content: mutableData,
			signature: try signer(mutableData.wireFormat)
		)
	}
}

public struct AnchorPublicKey: Sendable {
	let publicKey: any PublicSigningKey
	public let archive: TypedKeyMaterial

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

	func verify(signedMutable: SignedObject<IdentityMutableData>) throws -> IdentityMutableData
	{
		guard
			verifier(
				signedMutable.signature,
				try signedMutable.content.wireFormat
			)
		else {
			throw ProtocolError.authenticationError
		}
		return signedMutable.content
	}
}

extension AnchorPublicKey: Codable {
	public init(from decoder: any Decoder) throws {
		let container = try decoder.container(keyedBy: CodingKeys.self)
		let archive = try container.decode(TypedKeyMaterial.self, forKey: .archive)
		try self.init(archive: archive)
	}
	
	public func encode(to encoder: any Encoder) throws {
		var container = encoder.container(keyedBy: CodingKeys.self)
		try container.encode(self.archive, forKey: .archive)
	}
	
	enum CodingKeys: String, CodingKey {
		case archive
	}
}

extension AnchorPublicKey {
	//did/AnchorTo should be known as we needed it to fetch this
	public func verify(
		hello: AnchorHello,
		for destination: DependentIdentity
	) throws -> AnchorHello.Verified {

		let verifiedPackage = try verifyPackage(hello: hello, dependendentId: destination)
		let newAgentKey = try AgentPublicKey(
			archive: verifiedPackage.first.third.first
		)

		guard
			newAgentKey.verifier(
				verifiedPackage.second,
				try verifiedPackage.first
					.agentSignatureBody(dependentId: destination).wireFormat
			)
		else {
			throw ProtocolError.authenticationError
		}
		let content = verifiedPackage.first

		let publicAnchor = PublicAnchor(
			publicKey: self,
			attestation: destination
		)

		return .init(
			agent: .init(
				anchor: publicAnchor,
				agentKey: newAgentKey
			),
			succession: try publicAnchor.verify(proofs: content.first),
			policy: content.second,
			version: content.third.second,
			mlsKeyPackages: content.third.third,
		)
	}

	private func verifyPackage(
		hello: AnchorHello,
		dependendentId: DependentIdentity
	) throws -> AnchorHello.Package {
		guard
			verifier(
				hello.first,
				try AnchorHello.AnchorSignatureBody(
					dependentId: dependendentId,
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
		reply: AnchorWelcome,
		recipient: PublicAnchor
	) throws -> AnchorWelcome.Verified {
		let verifiedPackage = try verifyPackage(
			reply: reply,
			recipient: recipient,
		)
		let newAgentKey = try AgentPublicKey(
			archive: verifiedPackage.first.second
		)

		let agentSignatureBody = try verifiedPackage.first
			.agentSignatureBody(recipient: recipient)
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
			welcome: content.third,
			mlsWelcomeData: content.fourth
		)
	}

	private func verifyPackage(
		reply: AnchorWelcome,
		recipient: PublicAnchor,
	) throws -> AnchorWelcome.Package {
		guard
			verifier(
				reply.first,
				try AnchorWelcome.AnchorSignatureBody(
					encodedPackage: reply.second,
					knownAnchor: self,
					recipient: recipient,
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
		attestation: DependentIdentity
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
		guard result else {
			throw ProtocolError.authenticationError
		}
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
