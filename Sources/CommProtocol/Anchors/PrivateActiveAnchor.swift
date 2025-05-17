//
//  PrivateActiveAnchor.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 4/24/25.
//

import CryptoKit
import Foundation

public struct PrivateActiveAnchor {
	//public as this library doesn't understand the server registration types
	public let privateKey: AnchorPrivateKey
	public let publicKey: AnchorPublicKey
	public let attestation: DependentIdentity
	let history: [DatedProof]

	public var publicAnchor: PublicAnchor {
		.init(publicKey: publicKey, attestation: attestation)
	}

	public static func create(for destination: AnchorTo) -> Self {
		let anchorPrivateKey = AnchorPrivateKey()
		let attestationContents = DependentIdentity(anchorTo: destination)

		return .init(
			privateKey: anchorPrivateKey,
			attestation: attestationContents,
			history: []
		)
	}

	init(
		privateKey: AnchorPrivateKey,
		attestation: DependentIdentity,
		history: [DatedProof]
	) {
		self.privateKey = privateKey
		self.publicKey = privateKey.publicKey
		self.attestation = attestation
		self.history = history
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
			history: [
				.init(
					first: .init(
						predecessor: publicKey.archive,
						signature: signature
					),
					second: .now
				)
			]
		)
	}

	//handing off anchor cross-agent
	public func handOffAgent(
		previousAgent: PrivateAnchorAgent,
		newAgentKey: AgentPrivateKey,
		agentUpdate: AgentUpdate,
		groupContext: TypedDigest,
		mlsUpdateDigest: TypedDigest,
	) throws -> (PrivateAnchorAgent, AnchorHandoff) {
		guard let handoff = history.last?.first else {
			throw ProtocolError.incorrectAnchorState
		}

		let handoffContent = AnchorHandoff.Content(
			first: .init(
				publicKey: newAgentKey.publicKey,
				agentUpdate: agentUpdate
			),
			second: .init(
				first: publicKey.archive,
				second: handoff.signature
			)
		)

		let activeAnchorSignature = try privateKey.signer(
			try handoffContent
				.activeAnchorBody(
					groupContext: groupContext,
					knownAgent: previousAgent.publicKey
				).wireFormat
		)

		let newAgentSignature =
			try newAgentKey
			.signer(
				try handoffContent
					.activeAgentBody(
						groupContext: groupContext,
						mlsUpdateDigest: mlsUpdateDigest,
						knownAgent: previousAgent.publicKey
					).wireFormat
			)

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
				source: .handoff(anchorHandoff)
			),
			anchorHandoff
		)
	}
}

extension PrivateActiveAnchor {
	public func createHelloAgent() throws -> PrivateAnchorAgent {
		.init(
			privateKey: .init(),
			source:
				.hello(
					.init(
						anchorKey: publicKey,
						attestation: attestation,
						proofHistory: history
					)
				)
		)
	}

	public func generateHello(
		helloAgent: PrivateAnchorAgent,
		agentVersion: SemanticVersion,
		mlsKeyPackages: [Data],
		policy: AnchorPolicy,
		historyFilter: DatedProof.Filter = { _ in true }
	) throws -> AnchorHello {
		guard case .hello(let helloInputs) = helloAgent.source else {
			throw ProtocolError.incorrectAnchorState
		}
		guard helloInputs.anchorKey == publicKey else {
			throw ProtocolError.incorrectAnchorState
		}

		let filteredHistory = helloInputs.proofHistory
			.filter { historyFilter($0.second) }
			.map { $0.first }

		let content = AnchorHello.Content(
			first: helloInputs.attestation,
			second: filteredHistory,
			third: policy,
			fourth: .init(
				first: helloAgent.publicKey.id,
				second: agentVersion,
				third: mlsKeyPackages
			)
		)

		let package = AnchorHello.Package(
			first: content,
			second: try helloAgent.signer(content.agentSignatureBody().wireFormat)
		)

		let outerSignature = try privateKey.signer(
			try AnchorHello.AnchorSignatureBody(
				encodedPackage: try package.wireFormat,
				knownAnchor: helloInputs.anchorKey
			).wireFormat
		)

		return .init(
			first: outerSignature,
			second: try package.wireFormat
		)
	}
}

extension PrivateActiveAnchor {
	//agent isn't bound to the anchor until this step
	//so we expect the client to generate a fresh agent (no reuse)
	//generate an mlsWelcome, and provide them as input here
	public func createAnchorWelcome(
		agentUpdate: AgentUpdate,
		keyPackageData: Data,
		mlsWelcomeMessage: Data,
		mlsGroupId: DataIdentifier,
		newAgentKey: AgentPrivateKey,
		recipient: PublicAnchor,
		newSeqNo: UInt32
	) throws -> (PrivateAnchorAgent, AnchorWelcome) {
		let content = AnchorWelcome.Content(
			first: attestation,
			second: newAgentKey.publicKey.id,
			third: .init(
				first: agentUpdate,
				second: newSeqNo,
				third: .now,
				fourth: keyPackageData
			),
			fourth: mlsWelcomeMessage
		)

		let package = AnchorWelcome.Package(
			first: content,
			second:
				try newAgentKey
				.signer(
					content
						.agentSignatureBody(
							recipient: recipient,
							mlsGroupId: mlsGroupId
						)
						.wireFormat
				)
		)

		let outerSignature = try privateKey.signer(
			try AnchorWelcome.AnchorSignatureBody(
				encodedPackage: try package.wireFormat,
				knownAnchor: publicKey,
				recipient: recipient,
				mlsGroupId: mlsGroupId
			).wireFormat
		)

		let reply = AnchorWelcome(
			first: outerSignature,
			second: try package.wireFormat
		)

		return (
			.init(
				privateKey: newAgentKey,
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
		groupContext: TypedDigest,
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
			try handoffContent
				.activeAnchorBody(
					groupContext: groupContext,
					knownAgent: retiredAgent.publicKey
				).wireFormat
		)

		let newAgentSignature = try newAgent.signer(
			try handoffContent
				.activeAgentBody(
					groupContext: groupContext,
					mlsUpdateDigest: mlsUpdateDigest,
					knownAgent: retiredAgent.publicKey
				).wireFormat
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
		public let attestation: DependentIdentity.Archive
		let history: [Data]
	}

	public var archive: Archive {
		get throws {
			.init(
				privateKey: privateKey.archive.wireFormat,
				attestation: attestation.archive,
				history: history.compactMap { try? $0.wireFormat }
			)
		}
	}

	public init(archive: Archive) throws {
		let privateKey = try AnchorPrivateKey(
			archive: .init(wireFormat: archive.privateKey))
		self.init(
			privateKey: privateKey,
			attestation: try .init(archive: archive.attestation),
			history: archive.history.compactMap { try? .finalParse($0) }
		)
	}
}
