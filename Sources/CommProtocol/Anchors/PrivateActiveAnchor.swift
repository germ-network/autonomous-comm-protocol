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
	let handoff: AnchorHandoff.NewAnchor?

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
		handoff: AnchorHandoff.NewAnchor?
	) {
		self.privateKey = privateKey
		self.publicKey = privateKey.publicKey
		self.attestation = attestation
		self.handoff = handoff
	}

	public func handOff() throws -> PrivateActiveAnchor {
		let newAnchor = AnchorPrivateKey()

		let signature =
			try privateKey
			.signer(
				AnchorSuccession
					.signatureBody(
						attestation: attestation,
						predecessor: publicKey,
						successor: newAnchor.publicKey
					)
			)

		return .init(
			privateKey: newAnchor,
			attestation: attestation,
			handoff:  .init(
				first: newAnchor.publicKey.archive,
				second: signature
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

		let handoffContent = AnchorHandoff.Content(
			first: .init(
				publicKey: newAgentKey.publicKey,
				agentUpdate: agentUpdate
			),
			second: handoff
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

	//not public, we'll wrap this in a public function that encrypts
	public func createHello(
		agentVersion: SemanticVersion,
		mlsKeyPackages: [Data],
		newAgentKey: AgentPrivateKey,
		policy: AnchorPolicy
	) throws -> (PrivateAnchorAgent, AnchorHello) {
		let content = AnchorHello.Content(
			first: attestation,
			second: [],
			third: policy,
			fourth: .init(
				first: newAgentKey.publicKey.id,
				second: agentVersion,
				third: mlsKeyPackages
			)
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
		let handoff: Data?
	}

	public var archive: Archive {
		get throws {
			.init(
				privateKey: privateKey.archive.wireFormat,
				attestation: attestation.archive,
				handoff: try handoff?.wireFormat
			)
		}
	}

	public init(archive: Archive) throws {
		let privateKey = try AnchorPrivateKey(
			archive: .init(wireFormat: archive.privateKey))
		self.init(
			privateKey: privateKey,
			attestation: try .init(archive: archive.attestation),
			handoff: try .init(optionalWireformat: archive.handoff)
		)
	}
}

extension AnchorHandoff.NewAnchor {
	init?(optionalWireformat: Data?) throws {
		guard let optionalWireformat else { return nil }
		self = try .finalParse(optionalWireformat)
	}
}
