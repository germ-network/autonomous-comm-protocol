//
//  AgentTests.swift
//
//
//  Created by Mark Xue on 6/13/24.
//

import Foundation
import Testing
@testable import CommProtocol
import CryptoKit


struct AgentKeyTests {
    let privateKey = AgentPrivateKey(algorithm: .curve25519)
    
    @Test func testCoding() throws {
        let rehydrated: AgentPrivateKey = try .init(archive: privateKey.archive)
        #expect(privateKey.archive == rehydrated.archive )
        
        let publicKey = privateKey.publicKey
        let rehydratedPublic: AgentPublicKey = try .init(archive: publicKey.id)
        #expect(publicKey.id == rehydratedPublic.id)
    }
    
    @Test func testWireFormat() throws {
        let publicWireFormat = privateKey.publicKey.wireFormat
        
        let decodedPublic = try AgentPublicKey(wireFormat: publicWireFormat)
        #expect(privateKey.publicKey == decodedPublic)
        
        let symmetricKey = try TypedKeyMaterial(
            algorithm: .ChaCha20Poly1305,
            symmetricKey: SymmetricKey(size: .bits256)
        )
        
        #expect(throws: ProtocolError.typedKeyArchiveMismatch) {
            let _ = try AgentPrivateKey(archive: symmetricKey)
        }
        
        #expect(throws: ProtocolError.typedKeyArchiveMismatch) {
            let _ = try AgentPublicKey(archive: symmetricKey)
        }
    }
    
    @Test func testResourceSigning() throws {
        let resource = Resource(
            identifier: UUID().uuidString,
            plaintextDigest: SymmetricKey(size: .bits256).rawRepresentation,
            host: "example.com",
            symmetricKey: SymmetricKey(size: .bits256),
            expiration: Date.distantFuture
        )
        
        let signedResource = try privateKey.sign(agentSignableObject: resource)
        
        let validated = try privateKey
            .publicKey.validate(signedObject: signedResource)
        
        #expect(validated == resource)
    }
    
    @Test func testAddressSigning() throws {
        let address = ProtocolAddress(
            identifier: UUID().uuidString,
            serviceHost: "example.com",
            expiration: Date.distantFuture
        )
        
        let signedAddress = try privateKey.sign(agentSignableObject: [address])
        
        let validated = try privateKey
            .publicKey.validate(signedObject: signedAddress)
        
        #expect(validated.first == address)
    }
    
    @Test func testHash() throws {
        let firstKey = privateKey.publicKey
        let secondKey = AgentPrivateKey(algorithm: .curve25519).publicKey

        #expect(firstKey.hashValue == firstKey.hashValue)
        #expect(firstKey.hashValue != secondKey.hashValue)
    }
    
    @Test func testSignDelegateError() throws {
        let identityKey = IdentityPublicKey(concrete: Curve25519.Signing.PrivateKey().publicKey)
        let agentPubKey = privateKey.publicKey
        
        let agentData = AgentData(
            version: .init(major: 0, minor: 0, patch: 1),
            isAppClip: nil
        )
        
        let wrongAssertion = IdentityRelationshipAssertion(
            relationship: .successorAgent,
            subject: identityKey.id,
            object: agentPubKey.id,
            objectData: try JSONEncoder().encode(agentData)
        )
        #expect(throws: ProtocolError.signatureDisallowed) {
            let _ = try privateKey.sign(delegate: wrongAssertion)
        }
        
        let wrongIdAssertion = IdentityRelationshipAssertion(
            relationship: .delegateAgent,
            subject: identityKey.id,
            object: AgentPrivateKey(algorithm: .curve25519).publicKey.id,
            objectData: try JSONEncoder().encode(agentData)
        )
        #expect(throws: ProtocolError.signatureDisallowed) {
            let _ = try privateKey.sign(delegate: wrongIdAssertion)
        }
        
        let nilDataAssertion = IdentityRelationshipAssertion(
            relationship: .delegateAgent,
            subject: identityKey.id,
            object: agentPubKey.id,
            objectData: nil
        )
        #expect(throws: ProtocolError.signatureDisallowed) {
            let _ = try privateKey.sign(delegate: nilDataAssertion)
        }
        
        let falseData = IdentityRelationshipAssertion(
            relationship: .delegateAgent,
            subject: identityKey.id,
            object: agentPubKey.id,
            objectData: SymmetricKey(size: .bits128).rawRepresentation
        )
        #expect(throws: DecodingError.self) {
            let _ = try privateKey.sign(delegate: falseData)
        }
    }
    
    @Test func testSigningEarlyExit() {
        let identityData = IdentityMutableData(
            counter: 1,
            identityPublicKeyData: SymmetricKey(size: .bits256).rawRepresentation,
            pronouns: ["he/him"],
            aboutText: "test content"
        )
        #expect(throws: ProtocolError.incorrectSigner) {
            let _ = try privateKey.sign(agentSignableObject: identityData)
        }
    }
    
    @Test func testValidationDelegationErrors() throws {
        let agentData = AgentData(
            version: .init(major: 0, minor: 0, patch: 1),
            isAppClip: nil
        )
        
        let identity = try IdentityPrivateKey(algorithm: .curve25519)
        let (agentKey, referenceDelegation) = try identity.delegate(
            agentData: agentData
        )
        
        let incorrectSignature = try TypedSignature(
            prefix: .curve25519,
            checkedData: SymmetricKey(size: .bits256).rawRepresentation +  SymmetricKey(size: .bits256).rawRepresentation
        )
        
        #expect(throws: ProtocolError.authenticationError) {
            let invalidSignature = SignedIdentityRelationship(
                subjectSignature: referenceDelegation.objectSignature,
                objectSignature: incorrectSignature,
                assertion: referenceDelegation.assertion
            )
            
            let _ = try agentKey.publicKey.validate(delegation: invalidSignature)
        }
        
        #expect(throws: ProtocolError.authenticationError) {
            let _ = try privateKey.publicKey.validate(delegation: referenceDelegation)
        }
    }
}
