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

	@Test func testAnchorValidate() throws {
		let (encrypted, publicAnchorKey, seed) =
			try alexPrivateAnchor.produceAnchor()

		let publicAnchor = try PublicAnchor.create(
			encrypted: encrypted,
			publicKey: publicAnchorKey,
			seed: seed
		)
		#expect(publicAnchor.publicKey == publicAnchorKey)
		let didAnchor = try #require(
			publicAnchor.verified.anchorTo as? ATProtoDID
		)
		#expect(didAnchor == alexDID)
		#expect(publicAnchor.verified.previousAnchor == nil)
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
		let blairReplyAgent = try blairPrivateAnchor.createReplyAgent()
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

		let handoff = try alexPrivateAnchor.handOffNewAgent(
			agentUpdate: .mock(),
			from: alexAgent
		)
	}
}
