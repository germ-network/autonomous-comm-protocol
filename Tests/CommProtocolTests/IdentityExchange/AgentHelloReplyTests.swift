//
//  AgentHelloReplyTests.swift
//  CommProtocol
//
//  Created by Mark Xue on 8/2/24.
//

import CryptoKit
import Testing

@testable import CommProtocol

struct TestAgentHelloReply {
	let identityKey: IdentityPrivateKey
	let signedIdentity: SignedObject<CoreIdentity>
	let agentKey: AgentPrivateKey
	let introduction: IdentityIntroduction

	let agentHelloReply: AgentHelloReply

	init() throws {
		(identityKey, signedIdentity) =
			try Mocks
			.mockIdentity()

		let remoteAgentKey = AgentPrivateKey()

		(agentKey, introduction) =
			try identityKey
			.createNewDelegate(
				signedIdentity: signedIdentity,
				identityMutable: .mock(),
				agentType: .reply(
					remoteAgentId: remoteAgentKey.publicKey,
					seed: .init(width: .bits128)
				)
			)

		agentHelloReply = try agentKey.createAgentHelloReply(
			introduction: introduction,
			agentData: .mock(),
			groupIdSeed: .init(width: .bits256),
			welcomeMessage: SymmetricKey(size: .bits256).rawRepresentation
		)
	}

	@Test func testAgentHelloReply() throws {
		// Write your test here and use APIs like `#expect(...)` to check expected conditions.

	}

}
