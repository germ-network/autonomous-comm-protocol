//
//  PrivateActiveAnchor.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 4/24/25.
//

import CryptoKit
import Foundation

public struct PrivateActiveAnchor: Sendable {
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

		//accumulate the new proof onto the existing chain so continuity back to
		//the original key survives repeated rotations (verify(proofs:) walks the
		//full history predecessor-first)
		return .init(
			privateKey: newAnchor,
			attestation: attestation,
			history: history + [
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
		newAgentKey: PrivateAnchorAgent,
		agentUpdate: AgentUpdate,
		groupContext: TypedDigest,
		mlsUpdateDigest: TypedDigest,
	) throws -> AnchorHandoff {
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

		return AnchorHandoff(
			first: retiredAgentSignature,
			second: encodedPackage
		)
	}
}

extension PrivateActiveAnchor {
	public func createHelloAgent() -> PrivateAnchorAgent {
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
			.filter { historyFilter($0.second.date) }
			.map { $0.first }

		let content = AnchorHello.Content(
			first: filteredHistory,
			second: policy,
			third: .init(
				first: helloAgent.publicKey.id,
				second: agentVersion,
				third: mlsKeyPackages
			)
		)

		let package = AnchorHello.Package(
			first: content,
			second: try helloAgent.signer(
				content.agentSignatureBody(dependentId: attestation).wireFormat
			)
		)

		let outerSignature = try privateKey.signer(
			try AnchorHello.AnchorSignatureBody(
				dependentId: attestation,
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
		newAgentKey: AgentPrivateKey,
		recipient: PublicAnchor,
		newSeqNo: UInt32
	) throws -> (PrivateAnchorAgent, AnchorWelcome, AnchorWelcome.Content) {
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
						.agentSignatureBody(recipient: recipient)
						.wireFormat
				)
		)

		let outerSignature = try privateKey.signer(
			try AnchorWelcome.AnchorSignatureBody(
				encodedPackage: try package.wireFormat,
				knownAnchor: publicKey,
				recipient: recipient,
			).wireFormat
		)

		let reply = AnchorWelcome(
			first: outerSignature,
			second: try package.wireFormat
		)

		return (
			.init(
				privateKey: newAgentKey,
				source: .reply
			),
			reply,
			content
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

	/// Mint a handoff whose digests are OPAQUE bytes (v2 bodies).
	///
	/// Same flow and same wire structure as the typed overload — only the signature bodies
	/// differ, so `AnchorHandoff` itself is unchanged and the digests never travel in it. Pass
	/// the MLS backend's own values verbatim (TwoMLSPQ: `proposalContext` and `proposalHash`,
	/// or a digest from `PQDigest.over(_:)`). They are committed, never parsed, so this package
	/// no longer needs a case for the backend's hash — the backend can change suites without a
	/// release here.
	///
	/// Verify with `PublicAnchorAgent.verify(anchorHandoff:context:mlsUpdateDigest:)`'s matching
	/// opaque overload: the two are a pair, and a handoff minted here will NOT verify against
	/// the typed one (different discriminators, by design).
	public func createNewAgentHandoff(
		agentUpdate: AgentUpdate,
		newAgent: AgentPrivateKey,
		from retiredAgent: PrivateAnchorAgent,
		groupContext: Data,
		mlsUpdateDigest: Data,
	) throws -> AnchorHandoff {
		// The typed overload guaranteed a well-formed digest structurally; opaque bytes
		// move that to runtime. Empty is the one unambiguously degenerate value — a
		// handoff committing to nothing for a slot — and if BOTH ends plumbed empty
		// (a default-value integration bug), verification would succeed with the MLS
		// binding silently absent. Refuse at mint so the bug is loud at its source.
		guard !groupContext.isEmpty, !mlsUpdateDigest.isEmpty else {
			throw ProtocolError.unexpected("empty digest bytes in opaque handoff body")
		}
		let handoffContent = AnchorHandoff.Content(
			first: .init(
				publicKey: newAgent.publicKey,
				agentUpdate: agentUpdate
			),
			second: nil
		)

		let activeAnchorSignature = try privateKey.signer(
			try handoffContent
				.activeAnchorBodyV2(
					groupContext: groupContext,
					knownAgent: retiredAgent.publicKey
				).wireFormat
		)

		let newAgentSignature = try newAgent.signer(
			try handoffContent
				.activeAgentBodyV2(
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
			try AnchorHandoff.RetiredAgentBodyV2(
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
				history: try history.map { try $0.wireFormat }
			)
		}
	}

	public init(archive: Archive) throws {
		let privateKey = try AnchorPrivateKey(
			archive: .init(wireFormat: archive.privateKey))
		self.init(
			privateKey: privateKey,
			attestation: try .init(archive: archive.attestation),
			history: try archive.history.map { try .finalParse($0) }
		)
	}
}
