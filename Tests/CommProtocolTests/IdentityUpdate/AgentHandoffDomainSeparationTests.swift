//
//  AgentHandoffDomainSeparationTests.swift
//  CommProtocol
//
//  The AgentHandoff new-agent signing body is domain-separated only for agent
//  versions at/above AgentUpdate.pqDomainSeparationVersion; classical agents keep
//  the pre-separation body. Both branches must round-trip; classical must stay
//  byte-identical to the plain concatenation.
//

import CryptoKit
import Foundation
import Testing

@testable import CommProtocol

struct AgentHandoffDomainSeparationTests {
	private struct Fixture {
		let knownAgent: AgentPrivateKey
		let newAgent: AgentPrivateKey
		let newIdentity: IdentityPublicKey
		let context: TypedDigest
		let updateMessage: Data
		let agentData: AgentUpdate
		let tbs: AgentHandoff.NewAgentTBS

		// Body with no discriminator — the pre-separation (classical) layout.
		var plainBody: Data {
			get throws {
				try knownAgent.publicKey.wireFormat
					+ newIdentity.id.wireFormat
					+ context.wireFormat
					+ updateMessage
					+ agentData.wireFormat
			}
		}

		func signedHandoff() throws -> AgentHandoff {
			try AgentHandoff(
				first: agentData,
				second: newAgent.signer(tbs.formatForSigning)
			)
		}

		func validate(_ handoff: AgentHandoff) throws -> AgentUpdate {
			try handoff.validate(
				knownAgent: knownAgent.publicKey,
				newAgent: newAgent.publicKey,
				newAgentIdentity: newIdentity,
				context: context,
				updateMessage: updateMessage
			)
		}
	}

	private func fixture(version: SemanticVersion) -> Fixture {
		let knownAgent = AgentPrivateKey()
		let newAgent = AgentPrivateKey()
		let newIdentity = IdentityPrivateKey(algorithm: .curve25519).publicKey
		let context = TypedDigest(prefix: .sha256, over: Data("group-context".utf8))
		let updateMessage = Data("mls-leaf-node-update".utf8)
		let agentData = AgentUpdate(version: version, isAppClip: false, addresses: [])
		return .init(
			knownAgent: knownAgent,
			newAgent: newAgent,
			newIdentity: newIdentity,
			context: context,
			updateMessage: updateMessage,
			agentData: agentData,
			tbs: .init(
				knownAgentKey: knownAgent.publicKey,
				newAgentIdentity: newIdentity,
				context: context,
				updateMessage: updateMessage,
				agentData: agentData
			)
		)
	}

	// Below the threshold: no discriminator; body is the plain concatenation;
	// and the handoff round-trips. This is today's classical wire format.
	@Test func testSubThresholdOmitsDiscriminator() throws {
		let f = fixture(version: .init(major: 2, minor: 2, patch: 0))
		#expect(!f.agentData.domainSeparatesHandoff)

		let body = try f.tbs.formatForSigning
		#expect(!body.starts(with: AgentHandoff.NewAgentTBS.discriminator))
		#expect(try body == f.plainBody)

		#expect(try f.validate(f.signedHandoff()) == f.agentData)
	}

	// At/above the threshold: discriminator is prepended; the handoff round-trips.
	@Test func testAtThresholdIncludesDiscriminator() throws {
		let f = fixture(version: AgentUpdate.pqDomainSeparationVersion)
		#expect(f.agentData.domainSeparatesHandoff)

		let body = try f.tbs.formatForSigning
		#expect(body.starts(with: AgentHandoff.NewAgentTBS.discriminator))
		#expect(try body == AgentHandoff.NewAgentTBS.discriminator + f.plainBody)

		#expect(try f.validate(f.signedHandoff()) == f.agentData)
	}

	// The capability tier sits strictly between today's classical agent version
	// (2.2.0) and the domain-separation threshold, so advertising PQ capability
	// does not by itself flip the handoff format.
	@Test func testCapabilityVersionOrdering() throws {
		#expect(
			AgentUpdate.pqCapableVersion
				== SemanticVersion(major: 2, minor: 3, patch: 0)
		)
		#expect(
			SemanticVersion(major: 2, minor: 2, patch: 0) < AgentUpdate.pqCapableVersion
		)
		#expect(AgentUpdate.pqCapableVersion < AgentUpdate.pqDomainSeparationVersion)
	}

	// At exactly the capability tier (2.3.0): the agent is PQ-capable, but the
	// handoff body is still undiscriminated (== the plain concatenation) and the
	// handoff round-trips. The capability tier must not trip the format switch.
	@Test func testCapabilityTierOmitsDiscriminator() throws {
		let f = fixture(version: AgentUpdate.pqCapableVersion)
		#expect(f.agentData.isPQCapable)
		#expect(!f.agentData.domainSeparatesHandoff)

		let body = try f.tbs.formatForSigning
		#expect(!body.starts(with: AgentHandoff.NewAgentTBS.discriminator))
		#expect(try body == f.plainBody)

		#expect(try f.validate(f.signedHandoff()) == f.agentData)
	}

	// A signature over neither body is rejected (guards against a no-op verifier).
	@Test func testUnrelatedSignatureRejected() throws {
		let f = fixture(version: AgentUpdate.pqDomainSeparationVersion)
		let bogus = try AgentHandoff(
			first: f.agentData,
			second: f.newAgent.signer(Data("not the handoff body".utf8))
		)
		#expect(throws: ProtocolError.authenticationError) {
			_ = try f.validate(bogus)
		}
	}
}
