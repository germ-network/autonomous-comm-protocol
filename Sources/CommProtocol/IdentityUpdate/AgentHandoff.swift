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

    //for AgentPrivateKey.completeAgentHandoff
    public struct Input: Sendable {
        public let existingIdentity: IdentityPublicKey
        public let identityDelegate: IdentityDelegate
        public let signedIdentityMutable: SignedObject<IdentityMutableData>?
        public let establishedAgent: AgentPublicKey

        public init(
            existingIdentity: IdentityPublicKey,
            identityDelegate: IdentityDelegate,
            signedIdentityMutable: SignedObject<IdentityMutableData>?,
            establishedAgent: AgentPublicKey
        ) {
            self.existingIdentity = existingIdentity
            self.identityDelegate = identityDelegate
            self.signedIdentityMutable = signedIdentityMutable
            self.establishedAgent = establishedAgent
        }
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

extension AgentHandoff.Input: LinearEncodedQuad {
    public var first: TypedKeyMaterial { existingIdentity.id }
    public var second: IdentityDelegate { identityDelegate }
    public var third: SignedObject<IdentityMutableData>? { signedIdentityMutable }
    public var fourth: TypedKeyMaterial { establishedAgent.id }

    public init(first: First, second: Second, third: Third, fourth: Fourth) throws {
        self.init(
            existingIdentity: try .init(archive: first),
            identityDelegate: second,
            signedIdentityMutable: third,
            establishedAgent: try .init(archive: fourth)
        )
    }
}
