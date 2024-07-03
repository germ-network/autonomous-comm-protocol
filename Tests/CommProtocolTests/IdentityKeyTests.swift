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
    
    @Test func testHashDomainSeparation() throws {
        let baseKey = Curve25519.Signing.PrivateKey().publicKey
        let agentKey = AgentPublicKey(concrete: baseKey)
        let identityKey = IdentityPublicKey(concrete: baseKey)
        
        #expect(agentKey.hashValue != identityKey.hashValue)
    }
    
    @Test func testAgentHello() throws {
        let mutableFields = IdentityMutableData(
            counter: 2,
            identityPublicKeyData: privateKey.publicKey.id.wireFormat,
            pronouns: ["they/them"],
            aboutText: UUID().uuidString
        )
        
        let agentData = AgentData(
            version: .init(major: 0, minor: 1, patch: 1),
            isAppClip: nil
        )
        let (agentKey, signedDelegation) = try privateKey.delegate(
            agentData: agentData
        )
        
        //TODO: fill in a key package
        let keyPackageChoices = KeyPackageChoices()
        let address = ProtocolAddress(
            identifier: UUID().uuidString,
            serviceHost: "example.com",
            expiration: Date.distantFuture
        )
        
        let resource = Resource(
            identifier: UUID().uuidString,
            plaintextDigest: SymmetricKey(size: .bits256).rawRepresentation,
            host: "example.com",
            symmetricKey: SymmetricKey(size: .bits256),
            expiration: Date.distantFuture
        )
        
        let agentHello = AgentHello(
            signedIdentity: signedIdentity,
            signedMutableFields: try privateKey.sign(mutableData: mutableFields),
            agentDelegation: signedDelegation,
            keyPackages: try agentKey.sign(
                agentSignableObject: keyPackageChoices
            ),
            addresses: try agentKey.sign(agentSignableObject: [address]),
            imageResource: try agentKey.sign(agentSignableObject: resource),
            expiration: Date.distantFuture
        )
        
        let validatedHello = try agentHello.validated()
        
        #expect(validatedHello.coreIdentity == coreIdentity)
        #expect(validatedHello.signedIdentity.wireFormat == signedIdentity.wireFormat)
        #expect(validatedHello.mutableData == mutableFields)
        #expect(validatedHello.agentKey.id == agentKey.id)
        #expect(validatedHello.agentData == agentData)
        #expect(validatedHello.keyPackages.isEmpty)
        #expect(validatedHello.addresses.first == address)
        #expect(validatedHello.imageResource == resource)
        #expect(validatedHello.assertedExpiration == Date.distantFuture)
        
    }
}

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
