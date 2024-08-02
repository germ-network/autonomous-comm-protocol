//
//  AgentHelloReply.swift
//  CommProtocol
//
//  Created by Mark Xue on 8/2/24.
//

import Foundation

///While the AgentHello is not covered by a signature, this is transported in MLS authenticated content
///for the sender's leafNode, so the agent only needs to sign over the leafNode identity
///We do that by signing over the welcome message
public struct AgentHelloReply: Sendable {
    let signedIdentity: SignedObject<CoreIdentity>
    let identityMutable: SignedObject<IdentityMutableData>

    let agentDelegate: IdentityDelegate
    //AgentUpdate but with required imageResource
    let agentData: AgentUpdate
    let imageResource: Resource

    public struct NewAgentData: Sendable {

        public let version: SemanticVersion
        public let isAppClip: Bool
        public let addresses: [ProtocolAddress]
        public let keyPackage: TypedKeyPackage
        public let imageResource: Resource?
        public let expiration: Date
    }

    let agentSignatureWelcome: TypedSignature
}

//public struct AgentHelloReply: Codable, Sendable {
//    public let signedIdentity: CompleteSignedIdentity
//    //omit signedMutable for a follow-up message
//    public let scopedKeyAssertion: SignedIdentityRelationship
//
//    //not backwards compatible, send TransitionAgentReply if hello has missing agent/ scoped card
//    public let signedBody: SignedObject<HelloReply>
//
//}

//    public struct HelloReply: SignableObject, Codable, Sendable {
//        public static var typeName: SignableObjectTypes = .helloReply
//        public var typeName: SignableObjectTypes = .helloReply
//
//        public let channelIdentifier: ChannelIdentifier
//        public let ratchetKey: TypedRatchetSessionKeyArchive
//        public let date: Date
//        public let seqNo: UInt32
//
//        public init(channelIdentifier: ChannelIdentifier,
//                    ratchetKey: TypedRatchetSessionKeyArchive,
//                    date: Date,
//                    seqNo: UInt32) {
//            self.channelIdentifier = channelIdentifier
//            self.ratchetKey = ratchetKey
//            self.date = date
//            self.seqNo = seqNo
//        }
//    }
