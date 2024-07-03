//
//  AgentHello.swift
//
//
//  Created by Mark @ Germ on 7/2/24.
//

import Foundation

import Foundation
import CryptoKit

///Format for a card that gets symmetrically encrypted and exchanged
public struct AgentHello: Codable, Sendable {
    //Identity
    public let identity: Data //SignedIdentity.wireformat
    public let identityMutable: SignedObject<IdentityMutableData>?
    
    //Agent
    public let agentDelegate: Data //SignedIdentityRelationship.wireformat
    public let keyPackages: SignedObject<KeyPackageChoices>
    public let addresses: SignedObject<[ProtocolAddress]>
    public let imageResource: SignedObject<Resource>?
    public let expiration: Date
    
    init(
        signedIdentity: SignedIdentity,
        signedMutableFields: SignedObject<IdentityMutableData>?,
        agentDelegation: SignedIdentityRelationship,
        keyPackages: SignedObject<KeyPackageChoices>,
        addresses: SignedObject<[ProtocolAddress]>,
        imageResource: SignedObject<Resource>?,
        expiration: Date
    ) {
        self.identity = signedIdentity.wireFormat
        self.identityMutable = signedMutableFields
        self.agentDelegate = agentDelegation.wireFormat
        self.keyPackages = keyPackages
        self.addresses = addresses
        self.imageResource = imageResource
        self.expiration = expiration
    }
    
    public struct Validated: Sendable {
        public let coreIdentity: CoreIdentity //from the SignedIdentity
        public let signedIdentity: SignedIdentity
        public let mutableData: IdentityMutableData?
        public let agentKey: AgentPublicKey
        public let agentData: AgentData
        public let keyPackages: KeyPackageChoices
        public let addresses: [ProtocolAddress]
        public let imageResource: Resource?
        public let assertedExpiration: Date
        
        init(coreIdentity: CoreIdentity, signedIdentity: SignedIdentity, mutableData: IdentityMutableData?, agentKey: AgentPublicKey, agentData: AgentData, keyPackages: KeyPackageChoices, addresses: [ProtocolAddress], imageResource: Resource?, assertedExpiration: Date) {
            self.coreIdentity = coreIdentity
            self.signedIdentity = signedIdentity
            self.mutableData = mutableData
            self.agentKey = agentKey
            self.agentData = agentData
            self.keyPackages = keyPackages
            self.addresses = addresses
            self.imageResource = imageResource
            self.assertedExpiration = assertedExpiration
        }
    }
        
    public func validated() throws -> Validated {
        let signedIdentity = try SignedIdentity(wireFormat: identity)
        let identity = try signedIdentity.verifiedIdentity()
        let identityKey = try IdentityPublicKey(wireFormat: identity.id)
        
        let signedRelationship = try SignedIdentityRelationship(wireFormat: agentDelegate)
        
        let (agentKey, agentData) = try identityKey.validate(delegation: signedRelationship)
        
        return .init(
            coreIdentity: identity,
            signedIdentity: signedIdentity,
            mutableData: try identityKey.validate(signedMutableData: identityMutable),
            agentKey: agentKey,
            agentData: agentData,
            keyPackages: try agentKey.validate(signedKeyPackages: keyPackages),
            addresses: try agentKey.validate(signedAddresses: addresses),
            imageResource: try agentKey.validate(signedResource: imageResource),
            assertedExpiration: expiration
        )
    }
}

/*
 public struct AgentHelloReply: Codable, Sendable {
 }
 */
