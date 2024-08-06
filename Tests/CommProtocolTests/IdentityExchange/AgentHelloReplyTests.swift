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
    let coreIdentity: CoreIdentity
    let signedIdentity: SignedObject<CoreIdentity>
    let agentKey: AgentPrivateKey
    let introduction: IdentityIntroduction

    let agentHelloReply: AgentHelloReply

    init() throws {
        (identityKey, coreIdentity, signedIdentity) =
            try Mocks
            .mockIdentity()

        let context = try TypedDigest.mock()

        (agentKey, introduction) =
            try identityKey
            .createHelloDelegate(
                signedIdentity: signedIdentity,
                identityMutable: .mock(),
                imageResource: .mock(),
                context: context
            )

        agentHelloReply = try agentKey.createAgentHelloReply(
            introduction: introduction,
            agentData: .mock(),
            groupIdSeed: SymmetricKey(size: .bits256).rawRepresentation,
            welcomeMessage: SymmetricKey(size: .bits256).rawRepresentation
        )
    }

    @Test func testAgentHelloReply() async throws {
        // Write your test here and use APIs like `#expect(...)` to check expected conditions.

    }

}
