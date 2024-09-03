//
//  IdentityPropose.swift
//  CommProtocol
//
//  Created by Mark Xue on 7/26/24.
//

import Foundation

public struct IdentityDelegate: Sendable, Equatable {
    let newAgentId: AgentPublicKey

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

    func validate(
        knownIdentity: IdentityPublicKey,
        context: TypedDigest?
    ) throws -> AgentPublicKey {
        let knownSignatureBody = TBS(
            agentID: newAgentId.id,
            context: context
        ).formatForSigning
        guard
            knownIdentity.publicKey.isValidSignature(
                knownIdentitySignature.signature,
                for: knownSignatureBody
            )
        else {
            throw ProtocolError.authenticationError
        }
        return newAgentId
    }
}

extension IdentityDelegate: LinearEncodedPair {
    public var first: TypedKeyMaterial { newAgentId.id }
    public var second: TypedSignature { knownIdentitySignature }

    public init(first: TypedKeyMaterial, second: TypedSignature) throws {
        self.init(
            newAgentId: try .init(archive: first),
            knownIdentitySignature: second
        )
    }
}

///package the elements you need for a identity handoff
public struct IdentityHandoff: Equatable {
    let introduction: IdentityIntroduction
    //old key sign over over new identity pub Key + verb + TypedDigest
    struct PredecessorTBS {
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

    struct Validated {
        let newIdentity: CoreIdentity
        let signedNewIdentity: SignedObject<CoreIdentity>
        let newMutableData: IdentityMutableData
        let newAgentKey: AgentPublicKey
    }

    func validate(
        knownIdentity: IdentityPublicKey,
        context: TypedDigest
    ) throws -> Validated {
        let (newIdentity, introContents) = try introduction.validated(context: context)

        //verify predecessor signature over the new key + context
        let predecessorSignatureBody = PredecessorTBS(
            newIdentityPubKey: newIdentity.id,
            context: context
        ).formatForSigning
        guard
            knownIdentity.publicKey.isValidSignature(
                predecessorSignature.signature,
                for: predecessorSignatureBody
            )
        else {
            throw ProtocolError.authenticationError
        }

        return .init(
            newIdentity: newIdentity,
            signedNewIdentity: introduction.signedIdentity,
            newMutableData: introContents.mutableData,
            newAgentKey: introContents.agentKey
        )
    }
}

extension IdentityHandoff: LinearEncodedPair {
    public var first: IdentityIntroduction { introduction }
    public var second: TypedSignature { predecessorSignature }

    public init(first: IdentityIntroduction, second: TypedSignature) throws {
        self.init(
            introduction: first,
            predecessorSignature: second
        )
    }
}
