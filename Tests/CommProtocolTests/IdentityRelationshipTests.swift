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
        let firstAgentKey = firstAgent.publicKey
        
        let secondAgent = AgentPrivateKey(algorithm: .curve25519)
        let secondAgentKey = secondAgent.publicKey
        let objectData = SymmetricKey(size: .bits128).rawRepresentation
        
        let assertion = IdentityRelationshipAssertion(
            relationship: .successorIdentity,
            subject: firstAgentKey.id,
            object: secondAgentKey.id,
            objectData: objectData
        )
        
        let decoded = try IdentityRelationshipAssertion(wireformat: assertion.wireFormat)
        #expect(decoded.relationship == .successorIdentity)
        #expect(decoded.subject == firstAgentKey.id)
        #expect(decoded.object == secondAgentKey.id)
        #expect(decoded.objectData == objectData)
        
        let nilAssertion = IdentityRelationshipAssertion(
            relationship: .successorIdentity,
            subject: firstAgentKey.id,
            object: secondAgentKey.id,
            objectData: nil
        )
        let nilDecoded = try IdentityRelationshipAssertion(wireformat: nilAssertion.wireFormat)
        #expect(nilDecoded.relationship == .successorIdentity)
        #expect(nilDecoded.subject == firstAgentKey.id)
        #expect(nilDecoded.object == secondAgentKey.id)
        #expect(nilDecoded.objectData == nil)
    }

}
