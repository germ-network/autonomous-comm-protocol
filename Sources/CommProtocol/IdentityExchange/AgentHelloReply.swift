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

///Whereas in the prototype this struct was unwrapped from a basic message and used to
///form a channel, under MLS
///- we process a MLS welcome
///- we check the properties of the resulting group against our invitation
///- we process the stapled application message containing the AgentHelloReply
///- check the contents of the AgentHelloReply

public struct AgentHelloReply: Sendable {
    public let introduction: IdentityIntroduction
    public let agentData: AgentUpdate

    ///A seed to be mixed into the initial pair of agent id's to derive the underlying group Id
    public let groupIdSeed: Data
    public let agentSignatureWelcome: TypedSignature

    public let sentTime: Date  //just as messages assert local send time

}

extension AgentHelloReply: LinearEncodedQuintuple {
    public var first: IdentityIntroduction { introduction }
    public var second: AgentUpdate { agentData }
    public var third: Data { groupIdSeed }
    public var fourth: TypedSignature { agentSignatureWelcome }
    public var fifth: Date { sentTime }

    public init(
        first: IdentityIntroduction,
        second: AgentUpdate,
        third: Data,
        fourth: TypedSignature,
        fifth: Date
    ) throws {
        self.init(
            introduction: first,
            agentData: second,
            groupIdSeed: third,
            agentSignatureWelcome: fourth,
            sentTime: fifth
        )
    }
}
