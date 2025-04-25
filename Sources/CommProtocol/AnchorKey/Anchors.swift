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
	public let publicKey: AnchorPublicKey
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
}

extension PrivateActiveAnchor {
	//may want to reuse the seed if we eventually upload multiple keypackages
	public func createHello(
		agentVersion: SemanticVersion,
		mlsKeyPackages: [Data],
		seed: SymmetricKey
	) throws -> (AgentPrivateKey, Data) {
		let derivedKey = try publicKey.deriveKey(with: seed)

		let (newAgent, anchorHello) = try createHello(
			agentVersion: agentVersion,
			mlsKeyPackages: mlsKeyPackages
		)

		let encryptedHello = try ChaChaPoly.seal(
			try anchorHello.wireFormat,
			using: derivedKey
		).combined

		return (newAgent, encryptedHello)
	}

	//not public, we'll wrap this in a public function that encrypts
	func createHello(
		agentVersion: SemanticVersion,
		mlsKeyPackages: [Data]
	) throws -> (AgentPrivateKey, AnchorHello) {
		let newAgent = AgentPrivateKey()

		let identitySigned = try SignedContent<AnchorHello.IdentitySigned>
			.create(
				content: .init(agentKey: newAgent.publicKey),
				signer: privateKey.signer,
				formatter: { $0.formatForSigning(delegationType: .hello) }
			)

		//capture the public key
		let anchorPublicKey = publicKey
		let agentSigned = try SignedContent<AnchorHello.AgentSigned>
			.create(
				content: .init(
					version: agentVersion,
					mlsKeyPackages: mlsKeyPackages
				),
				signer: newAgent.signer,
				formatter: { try $0.formatForSigning(anchorKey: anchorPublicKey) }
			)

		return (
			newAgent,
			.init(
				attestation: attestation,
				delegate: identitySigned,
				agentState: agentSigned
			)
		)
	}
}

public struct RetiredAnchor {
	let publicKey: any PublicSigningKey
}

public struct PublicAnchor {
	public let publicKey: AnchorPublicKey
	public let verified: AnchorAttestation

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

		return try create(
			publicKey: publicKey,
			signedAttestation: try .finalParse(decrypted)
		)
	}

	static func create(
		publicKey: AnchorPublicKey,
		signedAttestation: SignedContent<AnchorAttestation>
	) throws -> Self {
		let verified = try signedAttestation.verified(
			formatter: publicKey.formatter,
			verifier: publicKey.verifier
		)
		return .init(publicKey: publicKey, verified: verified)
	}
}
