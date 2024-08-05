//
//  EncodingTests.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 7/31/24.
//

import CommProtocol
import Testing

///exercise the public api
struct APITests {
    let identityKey: IdentityPrivateKey
    let coreIdentity: CoreIdentity
    let signedIdentity: SignedObject<CoreIdentity>
    let agentKey: AgentPrivateKey
    let signedIntroduction: SignedObject<IdentityIntroduction.Contents>
    let agentHello: AgentHello

    init() throws {
        (identityKey, coreIdentity, signedIdentity) =
            try Mocks
            .mockIdentity()

        (agentKey, signedIntroduction) =
            try identityKey
            .createHelloDelegate(
                identityMutable: .mock(),
                context: nil
            )

        agentHello = try agentKey.createAgentHello(
            signedIdentity: signedIdentity,
            signedContents: signedIntroduction,
            signedAgentData: try agentKey.sign(
                helloData: .mock(),
                for: coreIdentity.id
            )
        )

    }

    @Test func testLifecycle() throws {
        let validated = try agentHello.validated()
    }
}
