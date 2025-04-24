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

public struct PrivateActiveAnchor {
	let privateKey: AnchorPrivateKey
	let attestation: AnchorAttestation

	public static func create(for did: ATProtoDID) throws -> Self {
		let anchorPrivateKey = AnchorPrivateKey()
		let attestationContents = AnchorAttestation.Contents(
			anchorTo: did,
			previousAnchor: nil
		)

		let signedContents = try SignedContent<AnchorAttestation.Contents>
			.init(
				content: attestationContents,
				signer: anchorPrivateKey.signer,
				formatter: { content in
					content
						.formatForSigning(
							anchorKey: anchorPrivateKey.publicKey)
				}
			)

		return .init(
			privateKey: anchorPrivateKey,
			attestation: .init(
				publicKey: anchorPrivateKey.publicKey,
				signedContents: signedContents
			)
		)
	}

	public func produceAnchor() throws -> (
		encrypted: Data,
		publicKey: AnchorPublicKey,
		seedGen: DataIdentifier
	) {
		//underlying generation is from a CryptoKit symmetric key
		let newSeed = DataIdentifier(width: .bits128)
		let newSeedKey = SymmetricKey(data: newSeed.identifier)
		let derivedKey = try attestation.publicKey
			.deriveKey(with: newSeedKey)

		let encodedAttestation = try attestation.signedContents.wireFormat
		let encryptedAttestation = try ChaChaPoly.seal(
			encodedAttestation,
			using: derivedKey
		).combined

		return (encryptedAttestation, attestation.publicKey, newSeed)
	}

	//verify anchor

	//public func produceAnchorIntro() -> (encrypted: Data, seedGen: DataIdentifier) {

}

public struct RetiredAnchor {
	let publicKey: any PublicSigningKey
}

public struct PublicAnchor {
	let publicKey: any PublicSigningKey
}

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

	//	//TODO: type constrain this for registration
	//	public func sign(over body: Data) throws -> TypedSignature {
	//		.init(
	//			signingAlgorithm: type,
	//			signature: try privateKey.signature(for: body)
	//		)
	//	}

	//	func sign(anchor: ATProtoAnchor) throws -> SignedObject<ATProtoAnchor> {
	//		.init(
	//			content: anchor,
	//			signature: .init(
	//				signingAlgorithm: type,
	//				signature:
	//					try privateKey
	//					.signature(
	//						for: anchor.formatForSigning(anchorKey: publicKey)
	//					)
	//			)
	//		)
	//	}
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

	//	public func verify(signedAnchor: SignedObject<ATProtoAnchor>) throws -> ATProtoAnchor {
	//		let format = signedAnchor.content.formatForSigning(anchorKey: self)
	//		guard
	//			publicKey.isValidSignature(
	//				signedAnchor.signature.signature,
	//				for: format
	//			)
	//		else {
	//			throw ProtocolError.authenticationError
	//		}
	//
	//		return signedAnchor.content
	//	}
}

extension TypedKeyMaterial {
	var asAnchorPublicKey: AnchorPublicKey {
		get throws {
			try .init(archive: self)
		}
	}
}
