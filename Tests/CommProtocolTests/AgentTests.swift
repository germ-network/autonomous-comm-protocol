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
        
        let encoded = try privateKey.encoded
        let decoded: AgentPrivateKey = try encoded.decoded()
        #expect(privateKey.id == decoded.id )
        
        let publicKey = privateKey.publicKey
        let encodedPublicKey = try publicKey.encoded
        let decodedPublicKey: AgentPublicKey = try encodedPublicKey.decoded()
        #expect(publicKey.id == decodedPublicKey.id)
    }
    
    @Test func testWireFormat() throws {
        let privateKey = AgentPrivateKey(algorithm: .curve25519)
        let publicWireFormat = try privateKey.publicKey.wireFormat
        
        let decodedPublic = try AgentPublicKey(wireFormat: publicWireFormat)
        #expect(privateKey.publicKey == decodedPublic)
    }
}
