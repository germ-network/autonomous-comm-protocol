//
//  AnchorAPIs.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 4/23/25.
//

import CommProtocol
import CryptoKit
import Testing

struct AnchorAPITests {
	let alexDID = ATProtoDID.mock()
	let alexPrivateAnchor: PrivateActiveAnchor
	let blairDID = ATProtoDID.mock()
	let blairPrivateAnchor: PrivateActiveAnchor

	init() throws {
		alexPrivateAnchor = .create(for: alexDID)
		blairPrivateAnchor = .create(for: blairDID)
	}

	@Test func testAnchorExchange() throws {
		//Alex initiates Hello
		let alexAgent = try alexPrivateAnchor.createHelloAgent()
		let hello =
			try alexPrivateAnchor
			.generateHello(
				helloAgent: alexAgent,
				agentVersion: .mock(),
				mlsKeyPackages: ["mock".utf8Data],
				policy: .closed
			)

		//Blair consumes the hello
		let alexPublicAnchor = alexPrivateAnchor.publicKey
		let verifiedAnchorHello =
			try alexPublicAnchor
			.verify(hello: hello, for: .init(anchorTo: alexDID))
		#expect(verifiedAnchorHello.agent.agentKey == alexAgent.publicKey)

		//Blair generates a reply
		let blairReplyAgentKey = AgentPrivateKey()
		//client creates an MLS welcome with the blairAgent
		let mockKeyPackage = SymmetricKey(size: .bits256).rawRepresentation
		let mockDigest = try TypedDigest.mock()
		let mockGroupId = SymmetricKey(size: .bits256).rawRepresentation

		let (blairReplyAgent, reply) = try blairPrivateAnchor.createReply(
			agentUpdate: .mock(),
			keyPackageData: mockKeyPackage,
			mlsWelcomeDigest: mockDigest,
			mlsGroupId: mockGroupId,
			newAgentKey: blairReplyAgentKey,
			recipient: alexPrivateAnchor.publicAnchor
		)

		//Alex processes the reply
		let verifiedReply = try blairPrivateAnchor.publicKey
			.verify(
				reply: reply,
				mlsWelcomeDigest: mockDigest,
				recipient: alexPrivateAnchor.publicAnchor,
				mlsGroupId: mockGroupId
			)
		#expect(verifiedReply.agent.agentKey == blairReplyAgent.publicKey)

		//Alex transitions from the hello agent to a steady-state agent
		//with an agent handoff

		let alexHandoffAgent = AgentPrivateKey()
		let mockUpdateDigest = try TypedDigest.mock()
		let handoff = try alexPrivateAnchor.createNewAgentHandoff(
			agentUpdate: .mock(),
			newAgent: alexHandoffAgent,
			from: alexAgent,
			mlsUpdateDigest: mockUpdateDigest
		)

		//Blair receives this
		let verifiedHandoff = try verifiedAnchorHello.agent.verify(
			anchorHandoff: handoff,
			mlsUpdateDigest: mockUpdateDigest
		)
		#expect(verifiedHandoff.newAnchor == false)
		#expect(verifiedHandoff.agent.agentKey == alexHandoffAgent.publicKey)

		//Finally, blair performs a full rollover
		let blairNewAnchor = try blairPrivateAnchor.handOff()
		let blairNewAgentKey = AgentPrivateKey()

		let mockBlairUpdateDigest = try TypedDigest.mock()
		let (blairNewAgent, blairHandoff) = try blairNewAnchor.handOffAgent(
			previousAgent: blairReplyAgent,
			newAgentKey: blairNewAgentKey,
			agentUpdate: .mock(),
			mlsUpdateDigest: mockBlairUpdateDigest
		)

		let verifiedBlairHandoff = try verifiedReply.agent.verify(
			anchorHandoff: blairHandoff,
			mlsUpdateDigest: mockBlairUpdateDigest
		)
		#expect(verifiedBlairHandoff.newAnchor == true)
		#expect(verifiedBlairHandoff.agent.anchorKey == blairNewAnchor.publicKey)
	}

	@Test func testArchive() throws {
		let archivedAlex = try alexPrivateAnchor.archive
		let restoredAlex = try PrivateActiveAnchor(archive: archivedAlex)

		//Alex initiates Hello
		let alexAgent = try alexPrivateAnchor.createHelloAgent()
		let alexHello =
			try alexPrivateAnchor
			.generateHello(
				helloAgent: alexAgent,
				agentVersion: .mock(),
				mlsKeyPackages: ["mock".utf8Data],
				policy: .closed
			)

		let alexAgentArchive = try alexAgent.archive
		let restoredHelloAgent = try PrivateAnchorAgent(archive: alexAgentArchive)
		#expect(restoredHelloAgent.publicKey == alexAgent.publicKey)

		//Blair consumes the hello
		let alexPublicAnchor = alexPrivateAnchor.publicKey
		let verifiedAnchorHello =
			try alexPublicAnchor
			.verify(hello: alexHello, for: .init(anchorTo: alexDID))
		let restoredAlexPublicAnchor = try PublicAnchorAgent(
			archive: verifiedAnchorHello.agent.archive
		)
		#expect(restoredAlexPublicAnchor.agentKey == alexAgent.publicKey)

		//		//Blair generates a reply
		//		let blairReplyAgent = blairPrivateAnchor.createNewAgent(type: .reply)
		//		//client creates an MLS welcome with the blairAgent
		//		let mockDigest = try TypedDigest.mock()
		//		let reply = try blairPrivateAnchor.createReply(
		//			agentVersion: .mock(),
		//			mlsWelcomeDigest: mockDigest,
		//			privateAgent: blairReplyAgent
		//		)
		//
		//		//Alex processes the reply
		//		let verifiedReply = try blairPrivateAnchor.publicKey
		//			.verify(reply: reply, mlsWelcomeDigest: mockDigest)
		//		#expect(verifiedReply.agent.agentKey == blairReplyAgent.publicKey)
		//
		//		//Alex transitions from the hello agent to a steady-state agent
		//		//with an agent handoff
		//
		//		let alexHandoffAgent = alexPrivateAnchor.createNewAgent()
		//		let mockUpdateDigest = try TypedDigest.mock()
		//		let handoff = try alexPrivateAnchor.createNewAgentHandoff(
		//			agentUpdate: .mock(),
		//			newAgent: alexHandoffAgent,
		//			from: alexAgent,
		//			mlsUpdateDigest: mockUpdateDigest
		//		)
		//
		//		//Blair receives this
		//
		//		let verifiedHandoff = try verifiedAnchorHello.agent.verify(
		//			anchorHandoff: handoff,
		//			mlsUpdateDigest: mockUpdateDigest
		//		)
		//		#expect(verifiedHandoff.newAnchor == false)
		//		#expect(verifiedHandoff.agent.agentKey == alexHandoffAgent.publicKey)
		//
		//		//Finally, blair performs a full rollover
		//		let blairNewAnchor = try blairPrivateAnchor.handOff()
		//		let blairNewAgent = blairNewAnchor.createNewAgent()
		//
		//		let mockBlairUpdateDigest = try TypedDigest.mock()
		//		let blairHandoff = try blairNewAnchor.handOffAgent(
		//			previousAgent: blairReplyAgent,
		//			newAgent: blairNewAgent,
		//			agentUpdate: .mock(),
		//			mlsUpdateDigest: mockBlairUpdateDigest
		//		)
		//
		//		let verifiedBlairHandoff = try verifiedReply.agent.verify(
		//			anchorHandoff: blairHandoff,
		//			mlsUpdateDigest: mockBlairUpdateDigest
		//		)
		//		#expect(verifiedBlairHandoff.newAnchor == true)
	}

	@Test func testAgentLifecycle() throws {
		//Alex creates a hello agent
		let alexAgent = try alexPrivateAnchor.createHelloAgent()
		let firstHello =
			try alexPrivateAnchor
			.generateHello(
				helloAgent: alexAgent,
				agentVersion: .mock(),
				mlsKeyPackages: ["mock".utf8Data],
				policy: .closed
			)

		//Alex changes the hello policy
		let revisedHello =
			try alexPrivateAnchor
			.generateHello(
				helloAgent: alexAgent,
				agentVersion: .mock(),
				mlsKeyPackages: ["mock".utf8Data],
				policy: .open
			)
	}
}
