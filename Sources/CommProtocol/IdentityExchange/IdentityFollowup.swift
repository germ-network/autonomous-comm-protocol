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
    public let agentSignedData: Data  //AgentTBS encoded
    public let agentSignature: Data

    public var addresses: [ProtocolAddress]?  //if dropped, can use rendezvous to reply

    struct AgentTBS {
        public let version: SemanticVersion  //update agent client version
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

//Stapled to every message

//Not worth it yet to optimize out 3 bytes version + 1 byte isAppClip
public struct AgentUpdate: Sendable, Equatable {
    public let version: SemanticVersion
    public let isAppClip: Bool
    public let addresses: [ProtocolAddress]
    public let imageResource: Resource?
}

//remove
extension AgentUpdate: Codable {}
