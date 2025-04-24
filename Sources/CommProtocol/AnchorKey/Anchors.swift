//
//  Anchors.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 4/24/25.
//

import CryptoKit
import Foundation

public struct PrivateActiveAnchor {
	let privateKey: AnchorPrivateKey
	let publicKey: AnchorPublicKey
	let attestation: SignedContent<AnchorAttestation>

	public static func create(for did: ATProtoDID) throws -> Self {
		let anchorPrivateKey = AnchorPrivateKey()
		let attestationContents = AnchorAttestation(
			anchorTo: did,
			previousAnchor: nil
		)

		let signedContents = try SignedContent<AnchorAttestation>
			.create(
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
			publicKey: anchorPrivateKey.publicKey,
			attestation: signedContents
		)
	}

	public func produceAnchor() throws -> (
		encrypted: Data,
		publicKey: AnchorPublicKey,
		seed: DataIdentifier
	) {
		//underlying generation is from a CryptoKit symmetric key
		let newSeed = DataIdentifier(width: .bits128)
		let newSeedKey = SymmetricKey(data: newSeed.identifier)
		let derivedKey = try publicKey.deriveKey(with: newSeedKey)

		let encryptedAttestation = try ChaChaPoly.seal(
			try attestation.wireFormat,
			using: derivedKey
		).combined

		return (encryptedAttestation, publicKey, newSeed)
	}

	//verify anchor

	//public func produceAnchorIntro() -> (encrypted: Data, seedGen: DataIdentifier) {

}

public struct RetiredAnchor {
	let publicKey: any PublicSigningKey
}

public struct PublicAnchor {
	let publicKey: AnchorPublicKey
	let verified: AnchorAttestation

	private init(publicKey: AnchorPublicKey, verified: AnchorAttestation) {
		self.publicKey = publicKey
		self.verified = verified
	}

	//counterpart to PrivateActiveAnchor.create
	public static func create(
		encrypted: Data,
		publicKey: AnchorPublicKey,
		seed: DataIdentifier
	) throws -> Self {
		let newSeedKey = SymmetricKey(data: seed.identifier)
		let derivedKey = try publicKey.deriveKey(with: newSeedKey)

		let decrypted = try ChaChaPoly.open(
			.init(combined: encrypted),
			using: derivedKey
		)
		let signedAttestation = try SignedContent<AnchorAttestation>
			.finalParse(decrypted)
		let verified = try signedAttestation.verified(
			formatter: publicKey.formatter,
			verifier: publicKey.verifier
		)
		return .init(publicKey: publicKey, verified: verified)
	}
}
