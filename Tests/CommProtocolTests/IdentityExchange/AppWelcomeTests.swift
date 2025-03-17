//
//  AppWelcomeTests.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 2/9/25.
//

import CommProtocol
import CryptoKit
import Testing

struct AppWelcomeTests {
    @Test func testValidation() throws {
        let myAgent = AgentPrivateKey(algorithm: .curve25519)

        let mockWelcome = try AppWelcome.mock(
            remoteAgentKey: myAgent.publicKey,
            keyPackageData: SymmetricKey(size: .bits256).rawRepresentation
        )

        let validated = try mockWelcome.validated(
            myAgent: myAgent.publicKey
        )

        #expect(
            validated.coreIdentity
                == mockWelcome.introduction.signedIdentity
                .content)
        #expect(
            validated.introContents == mockWelcome.introduction.signedContents.content)
        #expect(validated.welcomeContent == mockWelcome.signedContent.content)

    }

}
