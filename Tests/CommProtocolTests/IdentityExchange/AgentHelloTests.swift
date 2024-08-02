//
//  AgentHelloTests.swift
//  CommProtocol
//
//  Created by Mark Xue on 7/26/24.
//

import CryptoKit
import Foundation
import Testing

@testable import CommProtocol

struct AgentHelloTests {
    let privateKey: IdentityPrivateKey
    let coreIdentity: CoreIdentity
    let signedIdentity: SignedObject<CoreIdentity>
    let agentKey: AgentPrivateKey
    let signedDelegation: IdentityDelegate
    let agentHello: AgentHello

    init() throws {
        (privateKey, coreIdentity, signedIdentity) =
            try Mocks
            .mockIdentity()

        (agentKey, signedDelegation) =
            try privateKey
            .createAgentDelegate(context: nil)

        agentHello = try agentKey.createAgentHello(
            signedIdentity: signedIdentity,
            identityMutable:
                try privateKey
                .sign(mutableData: .mock()),
            agentDelegate: signedDelegation,
            agentTBS: .mock()
        )
    }

    @Test func testAgentHello() throws {
        let encoded = try agentHello.wireFormat
        //Not as critical, but output for comparison
        print("AgentHello size \(encoded.count)")

        let reencoded = try AgentHello.finalParse(encoded)

        let validatedHello = try reencoded.validated()

        #expect(validatedHello.coreIdentity == coreIdentity)
        #expect(validatedHello.agentKey == agentKey.publicKey)
        #expect(validatedHello.mutableData == validatedHello.mutableData)
        #expect(validatedHello.agentData == agentHello.signedAgentData.content)

    }

    @Test func testAgentHelloFailure() throws {
        let agentData = agentHello.signedAgentData.content
        let modifiedTBS = AgentHello.NewAgentData(
            version: agentData.version,
            isAppClip: true,
            addresses: agentData.addresses,
            keyChoices: agentData.keyChoices,
            imageResource: agentData.imageResource,
            expiration: agentData.expiration
        )
        let modifiedSignedAgentData = SignedObject<AgentHello.NewAgentData>(
            content: modifiedTBS,
            signature: agentHello.signedAgentData.signature
        )

        let modifiedTBSHello = AgentHello(
            signedIdentity: agentHello.signedIdentity,
            identityMutable: agentHello.identityMutable,
            agentDelegate: agentHello.agentDelegate,
            signedAgentData: modifiedSignedAgentData
        )

        #expect(throws: ProtocolError.authenticationError) {
            let _ = try modifiedTBSHello.validated()
        }
    }
}
