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

enum CommProposal {
    case sameAgent(TypedSignature) //over the new update message
    case sameIdentity(IdentityNewAgent) //used with multi-agents
    case newIdentity(IdentityHandoff, AgentHandoff)
    
    enum ProposalType: UInt8, LinearEnum {
        case sameAgent = 1
        case sameIdentity
        case newIdentity
    }
    
    
}



public struct AgentHandoff {
    let newAgentKey: AgentPublicKey
    
    struct KnownAgentTBS {
        let newAgentKey: AgentPublicKey
        let context: TypedDigest
        
        var formatForSigning: Data {
            Data("proposeAgent".utf8) + newAgentKey.wireFormat + context.wireFormat
        }
    }
    let knownAgentSignature: TypedSignature
    
    struct NewAgentTBS {
        let knownAgentKey: AgentPublicKey
        let context: TypedDigest
        let agentData: AgentUpdate
        let updateMessage: Data // stapled in the message AD
        
        var formatForSigning: Data {
            knownAgentKey.wireFormat + context.wireFormat + updateMessage
        }
    }
}

