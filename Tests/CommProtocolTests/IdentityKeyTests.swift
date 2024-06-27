//
//  IdentityKeyTests.swift
//
//
//  Created by Mark @ Germ on 6/15/24.
//

import Foundation
import Testing
@testable import CommProtocol
import CryptoKit

struct IdentityKeyTests {
    let privateKey: IdentityPrivateKey
    let coreIdentity: CoreIdentity
    let signedIdentity: SignedIdentity
    
    init() throws {
        let describedImage = DescribedImage(
            imageDigest: SymmetricKey(size: .bits128).rawRepresentation,
            altText: nil
        )
        
        (privateKey, coreIdentity, signedIdentity) = try IdentityPrivateKey
            .create(name: UUID().uuidString,
                    describedImage: describedImage)
    }
    
    @Test func testCreation() async throws {

        let rehydrated: IdentityPrivateKey = try .init(archive: privateKey.archive)
        #expect(privateKey.archive == rehydrated.archive)
        
        let publicKey = privateKey.publicKey
        let rehydratedPublic: IdentityPublicKey = try .init(archive: publicKey.id)
        #expect(publicKey == rehydratedPublic)
    }
    
    @Test func testWireFormat() throws {
        let publicWireFormat = privateKey.publicKey.id.wireFormat
        
        let decodedPublic = try IdentityPublicKey(wireFormat: publicWireFormat)
        //can't throw within the #require
        #expect(privateKey.publicKey == decodedPublic)
    }
    
    @Test func testDelegation() throws {
        let (agentKey, signedRelationship) = try privateKey.delegate(
            agentData: .init(version: .init(major: 0, minor: 1, patch: 1),
                             isAppClip: nil)
        )
        
        let decoded: SignedIdentityRelationship = try .init(wireFormat: signedRelationship.wireFormat)
        
        let (decodedAgent, agentData) = try privateKey.publicKey
            .validate(delegation: decoded)
        
        #expect(decodedAgent.id == agentKey.id)
        #expect(agentData.isAppClip == nil)
        #expect(agentData.version == .init(major: 0, minor: 1, patch: 1))
    }
}

