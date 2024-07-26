//
//  IdentityFollowup.swift
//
//
//  Created by Mark @ Germ on 6/27/24.
//

import Foundation

//Stripped nonessential data out of the helloReply / Welcome and send it in a second message within the newly constructed group / session
//TODO: Sha2 hashable
public struct IdentityFollowup: Sendable {
    public var signedMutableFields: SignedObject<IdentityMutableData>?
    public let imageResource: Resource?
    public let agentSignedData: Data //AgentTBS encoded
    public let agentSignature: Data
    
    public var addresses: [ProtocolAddress]? //if dropped, can use rendezvous to reply
    
    struct AgentTBS {
        public let version: SemanticVersion //update agent client version
        public let isAppClip: Bool?
        public let addresses: [ProtocolAddress]
    }
    
    public init(
        signedMutableFields: SignedObject<IdentityMutableData>? = nil,
        imageResource: Resource?,
        agentSignedData: Data,
        agentSignature: Data,
        addresses: [ProtocolAddress]? = nil
    ) {
        self.signedMutableFields = signedMutableFields
        self.imageResource = imageResource
        self.agentSignedData = agentSignedData
        self.agentSignature = agentSignature
        self.addresses = addresses
    }
    
//    public func sha2Hash(into hasher: inout SHA256) {
//        imageResource?.sha2Hash(into: &hasher)
//        signedMutableFields?.sha2Hash(into: &hasher)
//        addresses?.sha2Hash(into: &hasher)
//    }
}

//we staple this to every message
//send this as a SignedObject<AttachedData>
enum AttachedData: Codable {
    case agentUpdate(AgentUpdate) //same agent
    case agentProposal(AgentProposal, IdentityUpdate)
}

extension AttachedData: SignableObject {
    static let type: SignableObjectTypes = .agentAttached
}

//Stapled to every message as a
public struct AgentUpdate: Codable, Sendable {
    public let version: SemanticVersion?
    public let isAppClip: Bool? //ommitted when false
    public let addresses: [ProtocolAddress]
    public let update: Data //MLS update proposal message
    public let imageResource: Resource?
    public let expiration: Date
}

public struct AgentProposal: Codable {
    
}

public struct IdentityUpdate: Codable {
    
}
