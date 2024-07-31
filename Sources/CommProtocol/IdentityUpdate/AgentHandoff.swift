//
//  AgentHandoff.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 7/31/24.
//

import Foundation

public struct AgentHandoff {
    struct KnownAgentTBS {
        static let discriminator = Data("proposeAgent".utf8)
        let newAgentKey: AgentPublicKey
        let context: TypedDigest

        var formatForSigning: Data {
            Self.discriminator + newAgentKey.wireFormat + context.wireFormat
        }
    }
    let knownAgentSignature: TypedSignature

    struct NewAgentTBS {
        static let discriminator = Data("successorAgent".utf8)
        let knownAgentKey: AgentPublicKey
        let newAgentIdentity: IdentityPublicKey  //known or conveyed in the IdentityHandoff
        let context: TypedDigest  //known
        let agentData: Data
        let updateMessage: Data  // stapled in the message AD

        var formatForSigning: Data {
            knownAgentKey.wireFormat
                + newAgentIdentity.id.wireFormat
                + context.wireFormat
                + agentData
                + updateMessage
        }
    }
    let encodedAgentData: DeclaredWidthData
    let newAgentSignature: TypedSignature

    public var wireFormat: Data {
        knownAgentSignature.wireFormat
            + encodedAgentData.wireFormat
            + newAgentSignature.wireFormat
    }

    public struct Validated {
        let newAgent: AgentPublicKey
        let agentData: AgentUpdate
    }

    func validate(
        knownAgent: AgentPublicKey,
        newAgent: AgentPublicKey,
        newAgentIdentity: IdentityPublicKey,
        context: TypedDigest,
        updateMessage: Data
    ) throws -> AgentUpdate {
        let signatureBody = NewAgentTBS(
            knownAgentKey: knownAgent,
            newAgentIdentity: newAgentIdentity,
            context: context,
            agentData: encodedAgentData.body,
            updateMessage: updateMessage
        )
        .formatForSigning
        guard
            newAgent.publicKey.isValidSignature(
                newAgentSignature.signature,
                for: signatureBody
            )
        else {
            throw ProtocolError.authenticationError
        }

        return try JSONDecoder().decode(
            AgentUpdate.self,
            from: encodedAgentData.body
        )
    }
}

extension AgentHandoff: LinearEncodable {
    public static func parse(_ input: Data) throws -> (AgentHandoff, Int) {
        let (
            knownAgentSignature,
            encodedAgentData,
            newAgentSignature,
            consumed
        ) = try LinearEncoder.decode(
            TypedSignature.self,
            DeclaredWidthData.self,
            TypedSignature.self,
            input: input
        )
        return (
            .init(
                knownAgentSignature: knownAgentSignature,
                encodedAgentData: encodedAgentData,
                newAgentSignature: newAgentSignature
            ),
            consumed
        )
    }

}
