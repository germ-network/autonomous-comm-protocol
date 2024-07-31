//
//  IdentityPropose.swift
//  CommProtocol
//
//  Created by Mark Xue on 7/26/24.
//

import Foundation

///Need:
///* knownIdentity signature over new Agent
public struct IdentityDelegate: Sendable {
    let newAgentId: TypedKeyMaterial

    struct TBS {
        static let discriminator = Data("delegate".utf8)
        let agentID: TypedKeyMaterial
        let context: TypedDigest?

        var formatForSigning: Data {
            agentID.wireFormat + Self.discriminator + (context?.wireFormat ?? .init())
        }
    }
    let knownIdentitySignature: TypedSignature

    public var wireFormat: Data {
        newAgentId.wireFormat + knownIdentitySignature.wireFormat
    }

    func signatureOver(with context: TypedDigest?) -> Data {
        TBS(agentID: newAgentId, context: context).formatForSigning
    }
}

extension IdentityDelegate: LinearEncodable {
    public static func parse(
        _ input: Data
    ) throws -> (IdentityDelegate, Int) {
        let (agent, signature, consumed) = try LinearEncoder.decode(
            TypedKeyMaterial.self,
            TypedSignature.self,
            input: input
        )
        return (
            .init(
                newAgentId: agent,
                knownIdentitySignature: signature
            ),
            consumed
        )
    }

}

/////First of 4 signing steps to hand off an identity to a new identity
/////Previous Identity key over new identity pub Key + context
/////
/////Differentiated from the IdentitySuccessor as IdentityPropose doesn't nominate an agent
/////and IdentitySuccessor (the new key) must
//
//public struct IdentityPropose {
//    let newIdentityKey: IdentityPublicKey
//}
//
//extension IdentityPropose: SignableObject {
//    static public let type: SignableObjectTypes = .identityPropose
//}
//
/////New Identity key over
/////1. old identity key (omit)
/////2. context (repeat from 4)
/////3. newAgent PubKey (include)
//public struct IdentitySuccessor {
//    //Old Identity Key omitted in transit, included in signature
//    //context omitted in transit, included in signature
//    public let newAgentId: AgentPublicKey
//}

///package the elements you need for a identity handoff
public struct IdentityHandoff {
    let signedNewIdentity: SignedIdentity
    //over new identity pub Key + verb + TypedDigest
    struct PredecessorTBS {  // can just
        static let discriminator = Data("proposeIdentity".utf8)
        let newIdentityPubKey: IdentityPublicKey
        let context: TypedDigest  //representing groupId
        var formatForSigning: Data {
            Self.discriminator
                + newIdentityPubKey.id.wireFormat
                + context.wireFormat
        }
    }
    let predecessorSignature: TypedSignature

    struct SuccessorTBS {
        static let discriminator = Data("successorIdentity".utf8)
        let predecessorPubKey: IdentityPublicKey
        let context: TypedDigest  //representing groupId
        let newAgentKey: AgentPublicKey

        var formatForSigning: Data {
            Self.discriminator
                + predecessorPubKey.id.wireFormat
                + context.wireFormat
                + newAgentKey.wireFormat
        }
    }
    let newAgentKey: AgentPublicKey
    let successorSignature: TypedSignature

    public var wireFormat: Data {
        signedNewIdentity.wireFormat
            + predecessorSignature.wireFormat
            + newAgentKey.wireFormat
            + successorSignature.wireFormat
    }
}

extension IdentityHandoff: LinearEncodable {
    public static func parse(_ input: Data) throws -> (IdentityHandoff, Int) {
        throw LinearEncodingError.notImplemented
    }
}
