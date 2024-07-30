//
//  AgentPropose.swift
//  CommProtocol
//
//  Created by Mark Xue on 7/27/24.
//

import Foundation

///Order of operations:
///Start with a validated ID<>Agent<>LN having signed each other, for a given MLS groupID
///
///Order the data as follows

/// 1. Branch point new or same identity. convey this in enum
///     1 c. same Agent: existing agent over MLS update message
///     1 b. same identity: existing identity signature over the
///     1 a. new identity
///         1a.i: Old Identity Key over new Identity Key + context
///         1aii: New Identity key over old identity key + context + agent key

/// 2. Known Agent Key signs new Agent Key + context
/// 3. New Agent key signs a bundle, covering:
///     * known agent key
///     * context
///     * new agent's identity key
///     * new agent's associated data
///     * new agent's update message (enclosing the leafNode + MLS signing identity)
///
///
///Output:
///\[CommProposal.ProposalType.rawValue\]
/// * branch point
///     * \[TypedSignature.wireFormat\] \(sameAgent\)
///     * \[Identity
///[knownAgentSignature.wireFormat]
///

public enum CommProposal: LinearEncodable {
    //we don't, strictly speaking, need the type enum on the typed signature,
    //but this lets us parse the data structure without injecting the expected
    //types into the
    case sameAgent(TypedSignature)  //over the new update message
    case sameIdentity(IdentityDelegate, AgentHandoff)  //used with multi-agents
    case newIdentity(IdentityHandoff, AgentHandoff)

    enum ProposalType: UInt8, LinearEnum {
        case sameAgent = 1
        case sameIdentity
        case newIdentity
    }

    public enum Validated {
        case sameAgent
    }

    public static func parseAndValidate(
        _ input: Data,
        knownIdentity: IdentityPublicKey,
        knownAgent: AgentPublicKey,
        updateMessage: Data
    ) throws -> Validated {
        let result = try finalParse(input)
        switch result {
        case .sameAgent(let signature):
            guard
                knownAgent.publicKey.isValidSignature(
                    signature.signature,
                    for: updateMessage),
                signature.signingAlgorithm == knownAgent.type
            else {
                throw ProtocolError.authenticationError
            }
            return .sameAgent
        case .sameIdentity: throw LinearEncodingError.notImplemented
        case .newIdentity: throw LinearEncodingError.notImplemented

        }
    }

    public static func parse(_ input: Data) throws -> (CommProposal, Int) {
        let (type, remainder) = try ProposalType.continuingParse(input)
        switch type {
        case .sameAgent:
            let (signature, width) = try TypedSignature.parse(remainder)
            return (.sameAgent(signature), width + 1)
        case .sameIdentity: throw LinearEncodingError.notImplemented
        case .newIdentity: throw LinearEncodingError.notImplemented
        }

    }

    public var wireFormat: Data {
        get throws {
            switch self {
            case .sameAgent(let typedSignature):
                [ProposalType.sameAgent.rawValue] + typedSignature.wireFormat
            case .sameIdentity(let identityNewAgent):
                throw LinearEncodingError.notImplemented
            case .newIdentity(let identityHandoff, let agentHandoff):
                throw LinearEncodingError.notImplemented
            }
        }
    }
}

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
        let knownAgentKey: AgentPublicKey
        let newAgentIdentity: IdentityPublicKey  //known or conveyed in the IdentityHandoff
        let context: TypedDigest  //known
        let agentData: DeclaredWidthData
        let updateMessage: DeclaredWidthData  // stapled in the message AD

        var formatForSigning: Data {
            get throws {
                let encodedAgentData = agentData.wireFormat
                let encodedUpdate = updateMessage.wireFormat

                return knownAgentKey.wireFormat
                    + newAgentIdentity.id.wireFormat
                    + context.wireFormat
                    + encodedAgentData
                    + encodedUpdate
            }
        }
    }
    let encodedAgentData: DeclaredWidthData
    let newAgentSignature: TypedSignature
}
