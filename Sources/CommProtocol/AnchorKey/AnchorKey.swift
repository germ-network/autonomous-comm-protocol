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

struct AnchorPrivateKey: Sendable {
	private let privateKey: any PrivateSigningKey
	public let publicKey: AnchorPublicKey

	var type: SigningKeyAlgorithm {
		Swift.type(of: privateKey).signingAlgorithm
	}

	//for local storage
	public var archive: TypedKeyMaterial { .init(typedKey: privateKey) }

	public init(algorithm: SigningKeyAlgorithm = .curve25519) {
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

	init(archive: TypedKeyMaterial) throws {
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

	func deriveKey(with seed: SymmetricKey) throws -> SymmetricKey {
		HKDF<SHA256>
			.deriveKey(
				inputKeyMaterial: seed,
				salt: wireFormat,
				info: "anchorDerivation".utf8Data,
				outputByteCount: 32
			)
	}

	//signature, data
	var typedVerifier: @Sendable (TypedSignature, Data) -> Bool {
		{ signature, body in
			guard signature.signingAlgorithm == type else {
				return false
			}
			return publicKey.isValidSignature(signature.signature, for: body)
		}
	}

	//signature, data
	var verifier: @Sendable (Data, Data) -> Bool {
		{ signature, body in
			publicKey.isValidSignature(signature, for: body)
		}
	}
}

extension AnchorPublicKey {
	public func verify(
		encryptedHello: Data,
		seed: SymmetricKey
	) throws -> AnchorHello.Verified {
		let derivedKey = try deriveKey(with: seed)

		let decrypted = try ChaChaPoly.open(
			.init(combined: encryptedHello),
			using: derivedKey
		)

		let verifiedPackage = try verify(hello: .finalParse(decrypted))
		let newAgentKey = try AgentPublicKey(
			archive: verifiedPackage.first.second
		)

		guard
			newAgentKey.typedVerifier(
				verifiedPackage.second,
				try verifiedPackage.first.agentSignatureBody().wireFormat
			)
		else {
			throw ProtocolError.authenticationError
		}
		let content = verifiedPackage.first

		return .init(
			publicAnchor: .init(
				publicKey: self,
				verified: content.first
			),
			agentPublicKey: newAgentKey,
			version: content.third,
			mlsKeyPackages: content.fourth
		)
	}

	private func verify(hello: AnchorHello) throws -> AnchorHello.Package {
		guard
			typedVerifier(
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
	) throws -> AnchorReply.Verified {
		let verifiedPackage = try verify(reply: reply)
		let newAgentKey = try AgentPublicKey(
			archive: verifiedPackage.first.second
		)

		let agentSignatureBody = try verifiedPackage.first
			.agentSignatureBody(mlsWelcomeDigest: mlsWelcomeDigest)
			.wireFormat

		guard
			newAgentKey.typedVerifier(
				verifiedPackage.second,
				agentSignatureBody
			)
		else {
			throw ProtocolError.authenticationError
		}
		let content = verifiedPackage.first

		return .init(
			publicAnchor: .init(
				publicKey: self,
				verified: content.first
			),
			agentPublicKey: newAgentKey,
			version: content.third,
			seqNo: content.fourth,
			sentTime: content.fifth
		)
	}

	private func verify(reply: AnchorReply) throws -> AnchorReply.Package {
		guard
			typedVerifier(
				reply.first,
				try AnchorReply.AnchorSignatureBody(
					encodedPackage: reply.second,
					knownAnchor: self
				).wireFormat
			)
		else {
			throw ProtocolError.authenticationError
		}

		return try .finalParse(reply.second)
	}
}

extension AnchorPublicKey: Equatable {
	public static func == (lhs: AnchorPublicKey, rhs: AnchorPublicKey) -> Bool {
		lhs.wireFormat == rhs.wireFormat
	}
}

extension TypedKeyMaterial {
	var asAnchorPublicKey: AnchorPublicKey {
		get throws {
			try .init(archive: self)
		}
	}
}
