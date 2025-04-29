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
	let attestation: AnchorAttestation
	let handoff: Continuity?

	struct Continuity {
		let previousAnchor: AnchorPublicKey
		let handoff: AnchorHandoff.NewAnchor
	}

	public static func create(for did: ATProtoDID) throws -> Self {
		let anchorPrivateKey = AnchorPrivateKey()
		let attestationContents = AnchorAttestation(
			anchorType: .atProto,
			anchorTo: did
		)

		return .init(
			privateKey: anchorPrivateKey,
			publicKey: anchorPrivateKey.publicKey,
			attestation: attestationContents,
			handoff: nil
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

	public func handOff() throws -> PrivateActiveAnchor {
		let newAnchor = AnchorPrivateKey()
		let attestationContents = AnchorAttestation(
			anchorType: .atProto,
			anchorTo: attestation.anchorTo,
		)

		let content = AnchorHandoff.NewAnchor.Content(
			publicKey: newAnchor.publicKey,
			attestation: attestationContents
		)

		let signature =
			try privateKey
			.signer(content.retiredAnchorBody.wireFormat)

		return .init(
			privateKey: newAnchor,
			publicKey: publicKey,
			attestation: attestationContents,
			handoff: .init(
				previousAnchor: publicKey,
				handoff: .init(
					first: content,
					second: signature
				)
			)
		)
	}

	//handing off anchor cross-agent
	public func handOffAgent(
		previousAgent: PrivateAnchorAgent,
		newAgent: PrivateAnchorAgent,
		agentUpdate: AgentUpdate,
		mlsUpdateDigest: TypedDigest,
	) throws -> AnchorHandoff {
		guard let handoff else {
			throw ProtocolError.incorrectAnchorState
		}
		guard previousAgent.anchorPublicKey == handoff.previousAnchor else {
			throw ProtocolError.incorrectAnchorState
		}

		let handoffContent = AnchorHandoff.Content(
			first: .init(
				publicKey: newAgent.publicKey,
				agentUpdate: agentUpdate
			),
			second: handoff.handoff
		)

		let activeAnchorSignature = try privateKey.signer(
			try handoffContent.activeAnchorBody.wireFormat
		)

		let newAgentSignature = try newAgent.privateKey.signer(
			try handoffContent.activeAgentBody.wireFormat
		)

		let package = AnchorHandoff.Package(
			first: handoffContent,
			second: activeAnchorSignature,  //active anchor
			third: newAgentSignature  //new agent
		)

		let encodedPackage = try package.wireFormat
		let retiredAgentSignature = try previousAgent.privateKey.signer(
			try AnchorHandoff.RetiredAgentBody(
				encodedPackage: encodedPackage,
				mlsUpdateDigest: mlsUpdateDigest,
				knownAgent: previousAgent.publicKey
			).wireFormat
		)

		return .init(
			first: retiredAgentSignature,
			second: encodedPackage
		)
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
			first: attestation,
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

		let outerSignature = try privateKey.signer(
			try AnchorHello.AnchorSignatureBody(
				encodedPackage: try package.wireFormat,
				knownAnchor: publicKey
			).wireFormat
		)

		return (
			newAgent,
			.init(
				first: outerSignature,
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
	public func createNewAgent() -> PrivateAnchorAgent {
		.init(
			privateKey: .init(),
			anchorPublicKey: publicKey,
		)
	}

	public func createReply(
		agentVersion: SemanticVersion,
		mlsWelcomeDigest: TypedDigest,
		privateAgent: PrivateAnchorAgent,
	) throws -> AnchorReply {

		let content = AnchorReply.Content(
			first: attestation,
			second: privateAgent.publicKey.id,
			third: agentVersion,
			fourth: .random(in: .min...(.max)),
			fifth: .now
		)

		let package = AnchorReply.Package(
			first: content,
			second: try privateAgent.privateKey
				.signer(
					content
						.agentSignatureBody(
							mlsWelcomeDigest: mlsWelcomeDigest
						)
						.wireFormat
				)
		)

		let outerSignature = try privateKey.signer(
			try AnchorReply.AnchorSignatureBody(
				encodedPackage: try package.wireFormat,
				knownAnchor: publicKey
			).wireFormat
		)

		return .init(
			first: outerSignature,
			second: try package.wireFormat
		)
	}
}

extension PrivateActiveAnchor {
	//like with Reply, need to spawn the agent, create an MLS update with the
	//new agent as credential, then pass back here so the agent can sign over
	//the MLS update

	public func createNewAgentHandoff(
		agentUpdate: AgentUpdate,
		newAgent: PrivateAnchorAgent,
		from retiredAgent: AgentPrivateKey,
		mlsUpdateDigest: TypedDigest,
	) throws -> AnchorHandoff {
		let handoffContent = AnchorHandoff.Content(
			first: .init(
				publicKey: newAgent.publicKey,
				agentUpdate: agentUpdate
			),
			second: nil
		)

		let activeAnchorSignature = try privateKey.signer(
			try handoffContent.activeAnchorBody.wireFormat
		)

		let newAgentSignature = try newAgent.privateKey.signer(
			try handoffContent.activeAgentBody.wireFormat
		)

		let package = AnchorHandoff.Package(
			first: handoffContent,
			second: activeAnchorSignature,  //active anchor
			third: newAgentSignature  //new agent
		)

		let encodedPackage = try package.wireFormat
		let retiredAgentSignature = try retiredAgent.signer(
			try AnchorHandoff.RetiredAgentBody(
				encodedPackage: encodedPackage,
				mlsUpdateDigest: mlsUpdateDigest,
				knownAgent: retiredAgent.publicKey
			).wireFormat
		)

		return .init(
			first: retiredAgentSignature,
			second: encodedPackage
		)
	}
}

//public struct RetiredAnchor {
//	let publicKey: any PublicSigningKey
//}

public struct PublicAnchor {
	public let publicKey: AnchorPublicKey
	public let verified: AnchorAttestation
}
