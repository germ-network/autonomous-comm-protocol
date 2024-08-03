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
    let introduction: IdentityIntroduction
    let agentData: AgentUpdate
    let imageResource: Resource

    let groupIdSeed: Data
    let agentSignatureWelcome: TypedSignature

    let sentTime: Date  //just as messages assert local send time
}

extension AgentHelloReply: LinearEncodable {
    public static func parse(_ input: Data) throws -> (AgentHelloReply, Int) {
        throw LinearEncodingError.notImplemented
    }

    public var wireFormat: Data {
        get throws {
            try introduction.wireFormat
                + agentData.wireFormat
                + imageResource.wireFormat
                + DeclaredWidthData(body: groupIdSeed).wireFormat
        }
    }

}
