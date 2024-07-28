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
///* Known Agent Key signs new Agent Key
///*
///
///Output:
///[newAgentKey.wireFormat]
///[knownAgentSignature.wireFormat]
///

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

