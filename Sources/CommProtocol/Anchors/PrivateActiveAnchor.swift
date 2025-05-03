//
//  PrivateActiveAnchor.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 4/24/25.
//

import CryptoKit
import Foundation

public struct PrivateActiveAnchor {
	public let privateKey: AnchorPrivateKey
	public let publicKey: AnchorPublicKey
	public let attestation: AnchorAttestation
	let handoff: Continuity?

	struct Continuity {
		let previousAnchor: AnchorPublicKey
		let handoff: AnchorHandoff.NewAnchor
	}

	public static func create(for destination: AnchorTo) -> Self {
		let anchorPrivateKey = AnchorPrivateKey()
		let attestationContents = AnchorAttestation(anchorTo: destination)

		return .init(
			privateKey: anchorPrivateKey,
			attestation: attestationContents,
			handoff: nil
		)
	}

	init(
		privateKey: AnchorPrivateKey,
		attestation: AnchorAttestation,
		handoff: Continuity?
	) {
		self.privateKey = privateKey
		self.publicKey = privateKey.publicKey
		self.attestation = attestation
		self.handoff = handoff
	}

	//	public func produceAnchor() throws -> (
	//		encrypted: Data,
	//		publicKey: AnchorPublicKey,
	//		seed: DataIdentifier
	//	) {
	//		//underlying generation is from a CryptoKit symmetric key
	//		let newSeed = DataIdentifier(width: .bits128)
	//		let newSeedKey = SymmetricKey(data: newSeed.identifier)
	//		let derivedKey = publicKey.deriveKey(with: newSeedKey)
	//
	//		let encryptedAttestation = try ChaChaPoly.seal(
	//			try attestation.wireFormat,
	//			using: derivedKey
	//		).combined
	//
	//		return (encryptedAttestation, publicKey, newSeed)
	//	}

	public func handOff() throws -> PrivateActiveAnchor {
		let newAnchor = AnchorPrivateKey()
		let attestationContents = AnchorAttestation(
			anchorTo: attestation.anchorTo
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
		newAgentKey: AgentPrivateKey,
		agentUpdate: AgentUpdate,
		mlsUpdateDigest: TypedDigest,
	) throws -> (PrivateAnchorAgent, AnchorHandoff) {
		guard let handoff else {
			throw ProtocolError.incorrectAnchorState
		}
		guard previousAgent.anchorPublicKey == handoff.previousAnchor else {
			throw ProtocolError.incorrectAnchorState
		}

		let handoffContent = AnchorHandoff.Content(
			first: .init(
				publicKey: newAgentKey.publicKey,
				agentUpdate: agentUpdate
			),
			second: handoff.handoff
		)

		let activeAnchorSignature = try privateKey.signer(
			try handoffContent.activeAnchorBody.wireFormat
		)

		let newAgentSignature =
			try newAgentKey
			.signer(try handoffContent.activeAgentBody.wireFormat)

		let package = AnchorHandoff.Package(
			first: handoffContent,
			second: activeAnchorSignature,  //active anchor
			third: newAgentSignature  //new agent
		)

		let encodedPackage = try package.wireFormat
		let retiredAgentSignature = try previousAgent.signer(
			try AnchorHandoff.RetiredAgentBody(
				encodedPackage: encodedPackage,
				mlsUpdateDigest: mlsUpdateDigest,
				knownAgent: previousAgent.publicKey
			).wireFormat
		)

		let anchorHandoff = AnchorHandoff(
			first: retiredAgentSignature,
			second: encodedPackage
		)

		return (
			.init(
				privateKey: newAgentKey,
				anchorPublicKey: publicKey,
				source: .handoff(anchorHandoff)
			),
			anchorHandoff
		)
	}
}

extension PrivateActiveAnchor {
	//may want to reuse the seed if we eventually upload multiple keypackages
	public func createHello(
		agentVersion: SemanticVersion,
		mlsKeyPackages: [Data],
		newAgentKey: AgentPrivateKey,
		seed: SymmetricKey
	) throws -> (PrivateAnchorAgent, Data) {
		let derivedKey = publicKey.deriveKey(with: seed)

		let (newAgent, anchorHello) = try createHello(
			agentVersion: agentVersion,
			mlsKeyPackages: mlsKeyPackages,
			newAgentKey: newAgentKey
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
		mlsKeyPackages: [Data],
		newAgentKey: AgentPrivateKey
	) throws -> (PrivateAnchorAgent, AnchorHello) {
		let content = AnchorHello.Content(
			first: attestation,
			second: newAgentKey.publicKey.id,
			third: agentVersion,
			fourth: mlsKeyPackages
		)

		let package = AnchorHello.Package(
			first: content,
			second: try newAgentKey.signer(content.agentSignatureBody().wireFormat)
		)

		let outerSignature = try privateKey.signer(
			try AnchorHello.AnchorSignatureBody(
				encodedPackage: try package.wireFormat,
				knownAnchor: publicKey
			).wireFormat
		)

		let anchorHello = AnchorHello(
			first: outerSignature,
			second: try package.wireFormat
		)

		return (
			.init(
				privateKey: newAgentKey,
				anchorPublicKey: publicKey,
				source: .hello(anchorHello)
			),
			anchorHello
		)
	}
}

extension PrivateActiveAnchor {
	//agent isn't bound to the anchor until this step
	//so we expect the client to generate a fresh agent (no reuse)
	//generate an mlsWelcome, and provide them as input here
	public func createReply(
		agentVersion: SemanticVersion,
		mlsWelcomeDigest: TypedDigest,
		newAgentKey: AgentPrivateKey,
	) throws -> (PrivateAnchorAgent, AnchorReply) {
		let content = AnchorReply.Content(
			first: attestation,
			second: newAgentKey.publicKey.id,
			third: agentVersion,
			fourth: .random(in: .min...(.max)),
			fifth: .now
		)

		let package = AnchorReply.Package(
			first: content,
			second:
				try newAgentKey
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

		let reply = AnchorReply(
			first: outerSignature,
			second: try package.wireFormat
		)

		return (
			.init(
				privateKey: newAgentKey,
				anchorPublicKey: publicKey,
				source: .reply(reply)
			),
			reply
		)
	}
}

extension PrivateActiveAnchor {
	//like with Reply, need to spawn the agent, create an MLS update with the
	//new agent as credential, then pass back here so the agent can sign over
	//the MLS update

	public func createNewAgentHandoff(
		agentUpdate: AgentUpdate,
		newAgent: AgentPrivateKey,
		from retiredAgent: PrivateAnchorAgent,
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

		let newAgentSignature = try newAgent.signer(
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

extension PrivateActiveAnchor {
	public struct Archive: Codable {
		public let privateKey: Data  //TypedKeyMaterial.wireformat
		public let attestation: AnchorAttestation.Archive
		let continuity: Continuity.Archive?
	}

	public var archive: Archive {
		get throws {
			.init(
				privateKey: privateKey.archive.wireFormat,
				attestation: attestation.archive,
				continuity: try handoff?.archive
			)
		}
	}

	public init(archive: Archive) throws {
		let privateKey = try AnchorPrivateKey(
			archive: .init(wireFormat: archive.privateKey))
		self.init(
			privateKey: privateKey,
			attestation: try .init(archive: archive.attestation),
			handoff: try archive.continuity?.restored
		)
	}
}

extension PrivateActiveAnchor.Continuity {
	struct Archive: Codable {
		let previousAnchorKey: Data  //AnchorPublicKey.wireformat
		let handoff: Data  //AnchorHandoff.NewAnchor.wireformat

		var restored: PrivateActiveAnchor.Continuity {
			get throws {
				try .init(archive: self)
			}
		}
	}

	var archive: Archive {
		get throws {
			.init(
				previousAnchorKey: previousAnchor.wireFormat,
				handoff: try handoff.wireFormat
			)
		}
	}

	init(archive: Archive) throws {
		self.previousAnchor = try .init(wireFormat: archive.previousAnchorKey)
		self.handoff = try .finalParse(archive.handoff)
	}
}

//public struct RetiredAnchor {
//	let publicKey: any PublicSigningKey
//}
