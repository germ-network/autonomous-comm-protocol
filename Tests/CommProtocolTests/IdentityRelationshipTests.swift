//
//  IdentityRelationshipTests.swift
//
//
//  Created by Mark Xue on 6/25/24.
//

import Testing
@testable import CommProtocol

struct IdentityRelationshipTests {

    @Test func testWireFormat() async throws {
        let firstAgent = AgentPrivateKey(algorithm: .curve25519)
        let firstAgentKey = try firstAgent.publicKey.archive
        let secondAgent = AgentPrivateKey(algorithm: .curve25519)
        let secondAgentKey = try secondAgent.publicKey.archive
        
        let assertion = IdentityRelationshipAssertion(
            relationship: .successorIdentity,
            subject: firstAgentKey,
            object: secondAgentKey
        )
        
        let decoded = try IdentityRelationshipAssertion(wireformat: assertion.wireFormat)
        #expect(decoded.relationship == .successorIdentity)
        #expect(decoded.subject == firstAgentKey)
        #expect(decoded.object == secondAgentKey)
    }

}
