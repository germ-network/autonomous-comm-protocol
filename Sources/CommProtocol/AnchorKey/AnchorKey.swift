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

	var formatter: @Sendable (AnchorAttestation) throws -> Data {
		{ $0.formatForSigning(anchorKey: self) }
	}

	//signature, data
	var verifier: @Sendable (Data, Data) -> Bool {
		{ signature, body in
			publicKey.isValidSignature(signature, for: body)
		}
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
