//
//  KnownReply.swift
//  CommProtocol
//
//  Created by Mark at Germ  on 9/25/24.
//

import Foundation

//for when an identity intro isn't needed
public struct KnownReply: Sendable {
    public let agentData: AgentUpdate

    public let content: AgentHelloReply.Content
}


extension KnownReply: LinearEncodedPair {
    public var first: AgentUpdate { agentData }
    public var second: AgentHelloReply.Content { content }

    public init(
        first: AgentUpdate,
        second: AgentHelloReply.Content
    ) {
        self.init(agentData: first, content: second)
    }
}
