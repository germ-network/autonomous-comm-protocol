//
//  AgentHandoff.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 7/31/24.
//

import Foundation

public struct AgentHandoff: Equatable {
    struct NewAgentTBS {
        static let discriminator = Data("successorAgent".utf8)
        //All of these are injected and already known
        let knownAgentKey: AgentPublicKey
        let newAgentIdentity: IdentityPublicKey
        let context: TypedDigest
        let updateMessage: Data

        //transmitted in this object
        let agentData: AgentUpdate

        var formatForSigning: Data {
            get throws {
                try knownAgentKey.wireFormat
                    + newAgentIdentity.id.wireFormat
                    + context.wireFormat
                    + updateMessage
                    + agentData.wireFormat

            }
        }
    }
    let agentData: AgentUpdate
    let newAgentSignature: TypedSignature

    public var wireFormat: Data {
        get throws {
            try agentData.wireFormat
                + newAgentSignature.wireFormat
        }
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
        let signatureBody = try NewAgentTBS(
            knownAgentKey: knownAgent,
            newAgentIdentity: newAgentIdentity,
            context: context,
            updateMessage: updateMessage,
            agentData: agentData
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

        return agentData
    }
}

extension AgentHandoff: LinearEncodedPair {
    public var first: AgentUpdate { agentData }
    public var second: TypedSignature { newAgentSignature }

    public init(first: AgentUpdate, second: TypedSignature)
        throws
    {
        self.init(
            agentData: first,
            newAgentSignature: second
        )
    }
}
