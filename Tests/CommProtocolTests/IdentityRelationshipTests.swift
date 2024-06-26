//
//  IdentityRelationshipTests.swift
//
//
//  Created by Mark Xue on 6/25/24.
//

import Testing
import CryptoKit
@testable import CommProtocol

struct IdentityRelationshipTests {
    @Test func testInnerWireFormat() async throws {
        let firstAgent = AgentPrivateKey(algorithm: .curve25519)
        let firstAgentKey = try firstAgent.publicKey.archive
        let secondAgent = AgentPrivateKey(algorithm: .curve25519)
        let secondAgentKey = try secondAgent.publicKey.archive
        let objectData = SymmetricKey(size: .bits128).rawRepresentation
        
        let assertion = IdentityRelationshipAssertion(
            relationship: .successorIdentity,
            subject: firstAgentKey,
            object: secondAgentKey,
            objectData: objectData
        )
        
        let decoded = try IdentityRelationshipAssertion(wireformat: assertion.wireFormat)
        #expect(decoded.relationship == .successorIdentity)
        #expect(decoded.subject == firstAgentKey)
        #expect(decoded.object == secondAgentKey)
        #expect(decoded.objectData == objectData)
        
        let nilAssertion = IdentityRelationshipAssertion(
            relationship: .successorIdentity,
            subject: firstAgentKey,
            object: secondAgentKey,
            objectData: nil
        )
        let nilDecoded = try IdentityRelationshipAssertion(wireformat: nilAssertion.wireFormat)
        #expect(nilDecoded.relationship == .successorIdentity)
        #expect(nilDecoded.subject == firstAgentKey)
        #expect(nilDecoded.object == secondAgentKey)
        #expect(nilDecoded.objectData == nil)
    }

}
