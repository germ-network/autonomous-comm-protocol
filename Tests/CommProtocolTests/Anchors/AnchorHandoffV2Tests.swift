//
//  AnchorHandoffV2Tests.swift
//  CommProtocol
//
//  The opaque-digest handoff bodies: a handoff whose `groupContext` and
//  `mlsUpdateDigest` are bytes this package commits to but never interprets.
//
//  Two properties matter here. First, the round trip works on digests whose
//  algorithm this package cannot name — that is the whole point, since the hash
//  is a facet of the MLS backend's cipher suite. Second, v1 and v2 are mutually
//  unverifiable: their discriminators differ, so a signature made under one can
//  never be replayed as the other.
//

import AtprotoTypes
import AtprotoTypesMocks
import CommProtocolMocks
import CryptoKit
import Foundation
import Testing

@testable import CommProtocol

struct AnchorHandoffV2Tests {
	let alexDID = Atproto.DID.mock()
	let alexPrivateAnchor: PrivateActiveAnchor
	let blairDID = Atproto.DID.mock()
	let blairPrivateAnchor: PrivateActiveAnchor

	init() throws {
		alexPrivateAnchor = .create(for: alexDID)
		blairPrivateAnchor = .create(for: blairDID)
	}

	/// Digest bytes in a shape this package has no case for: tag 0x7F is not a
	/// `DigestTypes` value, so a `TypedDigest` could not represent this at all.
	/// The v2 bodies must carry it regardless — that is the contract.
	private func opaqueDigest(_ seed: UInt8) -> Data {
		Data([0x7F]) + Data(repeating: seed, count: 48)
	}

	/// Stand up a verified Alex→Blair anchor exchange and return the pieces a
	/// handoff needs.
	private func exchange() throws -> (
		alexAgent: PrivateAnchorAgent, verifiedByBlair: AnchorHello.Verified
	) {
		let alexAgent = alexPrivateAnchor.createHelloAgent()
		let hello = try alexPrivateAnchor.generateHello(
			helloAgent: alexAgent,
			agentVersion: .mock(),
			mlsKeyPackages: ["mock".utf8Data],
			policy: .closed
		)
		let verified = try alexPrivateAnchor.publicKey
			.verify(hello: hello, for: .init(anchorTo: alexDID))
		return (alexAgent, verified)
	}

	@Test func opaqueHandoffRoundTrips() throws {
		let (alexAgent, verified) = try exchange()
		let newAgent = AgentPrivateKey()
		let context = opaqueDigest(0xA1)
		let updateDigest = opaqueDigest(0xB2)

		let handoff = try alexPrivateAnchor.createNewAgentHandoff(
			agentUpdate: .mock(),
			newAgent: newAgent,
			from: alexAgent,
			groupContext: context,
			mlsUpdateDigest: updateDigest
		)

		let result = try verified.agent.verify(
			anchorHandoff: handoff,
			context: context,
			mlsUpdateDigest: updateDigest
		)
		#expect(result.newAnchor == false)
		#expect(result.agent.agentKey == newAgent.publicKey)
	}

	/// The verifier supplies its OWN reference digests — nothing is read out of
	/// the handoff — so the signature check is what compares them.
	@Test func wrongReferenceDigestsFailVerification() throws {
		let (alexAgent, verified) = try exchange()
		let newAgent = AgentPrivateKey()
		let context = opaqueDigest(0xA1)
		let updateDigest = opaqueDigest(0xB2)

		let handoff = try alexPrivateAnchor.createNewAgentHandoff(
			agentUpdate: .mock(),
			newAgent: newAgent,
			from: alexAgent,
			groupContext: context,
			mlsUpdateDigest: updateDigest
		)

		#expect(throws: (any Error).self) {
			_ = try verified.agent.verify(
				anchorHandoff: handoff,
				context: self.opaqueDigest(0xFF),
				mlsUpdateDigest: updateDigest
			)
		}
		#expect(throws: (any Error).self) {
			_ = try verified.agent.verify(
				anchorHandoff: handoff,
				context: context,
				mlsUpdateDigest: self.opaqueDigest(0xFF)
			)
		}
	}

	/// Domain separation across the two body generations: a v2 handoff must not
	/// verify as v1 even when the digest BYTES are identical, because the
	/// discriminators differ. (`TypedDigest.wireFormat` is exactly the bytes the
	/// opaque form carries, so this feeds both paths the same value — the only
	/// thing distinguishing them is the committed discriminator.)
	@Test func v2HandoffDoesNotVerifyAsV1() throws {
		let (alexAgent, verified) = try exchange()
		let newAgent = AgentPrivateKey()
		let typedContext = try TypedDigest.mock()
		let typedUpdate = try TypedDigest.mock()

		let v2Handoff = try alexPrivateAnchor.createNewAgentHandoff(
			agentUpdate: .mock(),
			newAgent: newAgent,
			from: alexAgent,
			groupContext: typedContext.wireFormat,
			mlsUpdateDigest: typedUpdate.wireFormat
		)

		#expect(throws: (any Error).self) {
			_ = try verified.agent.verify(
				anchorHandoff: v2Handoff,
				context: typedContext,
				mlsUpdateDigest: typedUpdate
			)
		}
	}

	/// And the converse.
	@Test func v1HandoffDoesNotVerifyAsV2() throws {
		let (alexAgent, verified) = try exchange()
		let newAgent = AgentPrivateKey()
		let typedContext = try TypedDigest.mock()
		let typedUpdate = try TypedDigest.mock()

		let v1Handoff = try alexPrivateAnchor.createNewAgentHandoff(
			agentUpdate: .mock(),
			newAgent: newAgent,
			from: alexAgent,
			groupContext: typedContext,
			mlsUpdateDigest: typedUpdate
		)

		#expect(throws: (any Error).self) {
			_ = try verified.agent.verify(
				anchorHandoff: v1Handoff,
				context: typedContext.wireFormat,
				mlsUpdateDigest: typedUpdate.wireFormat
			)
		}
	}

	/// The regression guard for the reason `.v2` is suffixed at all.
	///
	/// v1's `ActiveAgentBody` and `RetiredAgentBody` carry each OTHER's names — a
	/// frozen labeling bug (see the note in AnchorHandoff.swift). Domain separation
	/// depends on the committed strings being DISTINCT, not correctly named, so the
	/// swap is harmless; but it means the plain corrected names are occupied, which
	/// is why v2 cannot simply take them. This asserts the property that actually
	/// matters across the union of live body types.
	@Test func everyLiveDiscriminatorIsDistinct() {
		let all = [
			AnchorHandoff.ActiveAnchorBody.discriminator,
			AnchorHandoff.ActiveAgentBody.discriminator,
			AnchorHandoff.RetiredAgentBody.discriminator,
			AnchorHandoff.ActiveAnchorBodyV2.discriminator,
			AnchorHandoff.ActiveAgentBodyV2.discriminator,
			AnchorHandoff.RetiredAgentBodyV2.discriminator,
		]
		#expect(Set(all).count == all.count, "handoff discriminators must be pairwise distinct")
	}

	/// Pins the frozen swap so nobody "corrects" it in place and silently breaks
	/// every live relationship's handoff verification.
	@Test func v1SwapStaysFrozenAndV2IsCorrect() {
		#expect(AnchorHandoff.ActiveAgentBody.discriminator == "AnchorHandoff.RetiredAgentBody")
		#expect(AnchorHandoff.RetiredAgentBody.discriminator == "AnchorHandoff.ActiveAgentBody")

		#expect(
			AnchorHandoff.ActiveAnchorBodyV2.discriminator == "AnchorHandoff.ActiveAnchorBody.v2")
		#expect(
			AnchorHandoff.ActiveAgentBodyV2.discriminator == "AnchorHandoff.ActiveAgentBody.v2")
		#expect(
			AnchorHandoff.RetiredAgentBodyV2.discriminator == "AnchorHandoff.RetiredAgentBody.v2")
	}
}
