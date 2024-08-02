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
    let signedDelegation: IdentityDelegate
    let agentHello: AgentHello

    init() throws {
        (identityKey, coreIdentity, signedIdentity) =
            try Mocks
            .mockIdentity()

        (agentKey, signedDelegation) =
            try identityKey
            .createAgentDelegate(context: nil)

        agentHello = try agentKey.createAgentHello(
            signedIdentity: signedIdentity,
            identityMutable:
                try identityKey
                .sign(mutableData: .mock()),
            agentDelegate: signedDelegation,
            newAgentData: .mock()
        )
    }

    @Test func testLifecycle() throws {
        let validated = try agentHello.validated()
    }
}
