//
//  IdentityFollowup.swift
//
//
//  Created by Mark @ Germ on 6/27/24.
//

import Foundation

//generically useful as an identity follow-on
//send optional data as a follow-up message
//TODO: Sha2 hashable
public struct IdentityFollowup: Sendable {
    public let agentKey: AgentPublicKey
    public let imageResource: Resource?
    public var signedMutableFields: SignedObject<IdentityMutableData>?
    public var addresses: SignedObject<[ProtocolAddress]>? //if dropped, can use rendezvous to reply
    
    public init(agentKey: AgentPublicKey,
                imageResource: Resource?,
                signedMutableFields: SignedObject<IdentityMutableData>?,
                addresses: SignedObject<[ProtocolAddress]>?) {
        self.agentKey = agentKey
        self.imageResource = imageResource
        self.signedMutableFields = signedMutableFields
//        self.addresses = addresses
    }
    
//    public func sha2Hash(into hasher: inout SHA256) {
//        imageResource?.sha2Hash(into: &hasher)
//        signedMutableFields?.sha2Hash(into: &hasher)
//        addresses?.sha2Hash(into: &hasher)
//    }
}
