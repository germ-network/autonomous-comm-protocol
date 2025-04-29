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
		alexPrivateAnchor = try .create(for: alexDID)
		blairPrivateAnchor = try .create(for: blairDID)
	}

	@Test func testAnchorExchange() throws {
		//Alex initiates Hello
		let seed = DataIdentifier(width: .bits128)
		let seedKey = SymmetricKey(data: seed.identifier)

		let (alexAgent, encryptedHello) =
			try alexPrivateAnchor
			.createHello(
				agentVersion: .mock(),
				//parse seems to fail with empty data
				mlsKeyPackages: ["mock".utf8Data],
				seed: seedKey
			)

		//Blair consumes the hello
		let alexPublicAnchor = alexPrivateAnchor.publicKey
		let verifiedAnchorHello = try alexPublicAnchor.verify(
			encryptedHello: encryptedHello,
			seed: seedKey
		)
		#expect(verifiedAnchorHello.agentPublicKey == alexAgent.publicKey)

		//Blair generates a reply
		let blairReplyAgent = blairPrivateAnchor.createNewAgent()
		//client creates an MLS welcome with the blairAgent
		let mockDigest = try TypedDigest.mock()
		let reply = try blairPrivateAnchor.createReply(
			agentVersion: .mock(),
			mlsWelcomeDigest: mockDigest,
			privateAgent: blairReplyAgent
		)

		//Alex processes the reply
		let verified = try blairPrivateAnchor.publicKey
			.verify(reply: reply, mlsWelcomeDigest: mockDigest)
		#expect(verified.agentPublicKey == blairReplyAgent.publicKey)

		//Alex transitions from the hello agent to a steady-state agent
		//with an agent handoff

		let alexHandoffAgent = alexPrivateAnchor.createNewAgent()
		let mockUpdateDigest = try TypedDigest.mock()
		let handoff = try alexPrivateAnchor.createNewAgentHandoff(
			agentUpdate: .mock(),
			newAgent: alexHandoffAgent,
			from: alexAgent,
			mlsUpdateDigest: mockUpdateDigest
		)

		//Blair receives this
		let blairLocal = PublicAnchorAgent(
			anchorkey: verifiedAnchorHello.publicAnchor.publicKey,
			agentKey: verifiedAnchorHello.agentPublicKey
		)

		let verifiedHandoff = try blairLocal.verify(
			anchorHandoff: handoff,
			mlsUpdateDigest: mockUpdateDigest
		)

	}
}
