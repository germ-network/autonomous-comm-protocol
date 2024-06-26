//
//  AgentTests.swift
//
//
//  Created by Mark Xue on 6/13/24.
//

import Foundation
import Testing
@testable import CommProtocol


struct AgentKeyTests {
    @Test func testCoding() throws {
        let privateKey = AgentPrivateKey(algorithm: .curve25519)
        
        let rehydrated: AgentPrivateKey = try .init(archive: privateKey.archive)
        #expect(privateKey.archive == rehydrated.archive )
        
        let publicKey = privateKey.publicKey
        let rehydratedPublic: AgentPublicKey = try .init(archive: publicKey.id)
        #expect(publicKey.id == rehydratedPublic.id)
    }
    
    @Test func testWireFormat() throws {
        let privateKey = AgentPrivateKey(algorithm: .curve25519)
        let publicWireFormat = privateKey.publicKey.wireFormat
        
        let decodedPublic = try AgentPublicKey(wireFormat: publicWireFormat)
        #expect(privateKey.publicKey == decodedPublic)
    }
}
