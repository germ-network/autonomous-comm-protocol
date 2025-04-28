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
			anchorType: .atProto,
			anchorTo: did,
			previousAnchor: nil
		)

		let signedContents = try SignedContent<AnchorAttestation>
			.create(
				content: attestationContents,
				signer: anchorPrivateKey.signer,
				formatter: { content in
					try content
						.formatForSigning(
							anchorKey: anchorPrivateKey.publicKey
						)
						.wireFormat
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

		let content = AnchorHello.Content(
			first: attestation.content,
			second: newAgent.publicKey.id,
			third: agentVersion,
			fourth: mlsKeyPackages
		)

		let package = AnchorHello.Package(
			first: content,
			second:
				try newAgent
				.signer(content.agentSignatureBody().wireFormat)
		)

		return (
			newAgent,
			.init(
				first: try privateKey.signer(
					try AnchorHello.AnchorSignatureBody(
						encodedPackage: try package.wireFormat,
						knownAnchor: publicKey
					).wireFormat
				),
				second: try package.wireFormat
			)
		)
	}
}

extension PrivateActiveAnchor {
	//have to break this into 2 steps
	//1. generate delegate agent
	//client then generates welcome bound to the agent id
	//2. generate appWelcome bound to the welcome

	//can then encrypt to the HPKE key in the hello
	public func createReplyAgent() throws -> PrivateAnchorAgent {
		let newAgent = AgentPrivateKey()

		let anchorDelegation = try SignedContent<AnchorDelegation>
			.create(
				content: .init(agentKey: newAgent.publicKey),
				signer: privateKey.signer,
				formatter: {
					try $0.formatForSigning(delegationType: .reply).wireFormat
				}
			)

		return .init(
			privateKey: newAgent,
			anchorPublicKey: publicKey,
			attestation: attestation,
			delegation: anchorDelegation,
			delegateType: .reply
		)
	}
}

extension PrivateActiveAnchor {
	public func handOffNewAgent(
		agentUpdate: AgentUpdate,
		from predecessorAgent: AgentPrivateKey,
	) throws -> AnchorHandoff {
		let newAgent = AgentPrivateKey()
		let newAgentData = AnchorHandoff.Agent.NewData(
			anchorDelegation: .init(agentKey: newAgent.publicKey),
			agentUpdate: agentUpdate
		)

		let anchorSignature = try privateKey.signer(
			try newAgentData
				.anchorSigningFormat(
					newAnchorKey: publicKey,
					anchorAttestation: attestation.content,
					replacing: nil
				)
				.wireFormat
		)

		let predecessorSignature = try predecessorAgent.signer(
			//			.signAsPredecessor(
			newAgentData
				.predecessorSigningFormat(
					predecessor: predecessorAgent.publicKey
				)
				.wireFormat
		)

		let successorSignature = try newAgent.signer(
			newAgentData
				.successorSigningFormat(knownAgent: predecessorAgent.publicKey)
				.wireFormat
		)

		return .init(
			newAnchor: nil,
			newAgent: .init(
				newAgent: .init(
					anchorDelegation: .init(agentKey: newAgent.publicKey),
					agentUpdate: agentUpdate
				),
				predecessorSignature: predecessorSignature,
				successorSignature: successorSignature,
				anchorSignature: anchorSignature
			)
		)
	}

	//	public func handOffNewAnchor(from predecessor: PrivateAnchorAgent,
	//fromAgent: PrivateAnchorAgent) -> AnchorHandoff {
	//
	//	}
}

public struct RetiredAnchor {
	let publicKey: any PublicSigningKey
}

public struct PublicAnchor {
	public let publicKey: AnchorPublicKey
	public let verified: AnchorAttestation

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
