//
//  AgentHelloReply.swift
//  CommProtocol
//
//  Created by Mark Xue on 8/2/24.
//

import Foundation

///This is now deprecated and used in the PairMLS session type only
///This has the disadvantage of needing to process thek MLS commit to decrypt
///the Applicationmessage

///form a channel, under MLS
///- we process a MLS welcome
///- we check the properties of the resulting group against our invitation
///- we process the stapled application message containing the AgentHelloReply
///- check the contents of the AgentHelloReply

public struct AgentHelloReply: Sendable {
    public let introduction: IdentityIntroduction
    public let agentData: AgentUpdate
    public let content: Content

    public struct Content: Sendable {
        ///A seed to be mixed into the initial pair of agent id's to derive the underlying group Id
        public let groupIdSeed: DataIdentifier
        public let agentSignatureWelcome: TypedSignature
        public let seqNo: UInt32  //sets the initial seqNo
        public let sentTime: Date  //just as messages assert local send time
    }
}

extension AgentHelloReply: LinearEncodedTriple {
    public var first: IdentityIntroduction { introduction }
    public var second: AgentUpdate { agentData }
    public var third: Content { content }

    public init(
        first: IdentityIntroduction,
        second: AgentUpdate,
        third: Content
    ) {
        self.init(introduction: first, agentData: second, content: third)
    }
}

extension AgentHelloReply.Content: LinearEncodedQuad {
    public var first: DataIdentifier { groupIdSeed }
    public var second: TypedSignature { agentSignatureWelcome }
    public var third: UInt32 { seqNo }
    public var fourth: Date { sentTime }

    public init(
        first: DataIdentifier,
        second: TypedSignature,
        third: UInt32,
        fourth: Date
    ) throws {
        self.init(
            groupIdSeed: first,
            agentSignatureWelcome: second,
            seqNo: third,
            sentTime: fourth
        )
    }
}
