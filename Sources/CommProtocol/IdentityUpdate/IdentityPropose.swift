//
//  IdentityPropose.swift
//  CommProtocol
//
//  Created by Mark Xue on 7/26/24.
//

import Foundation

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

    func validate(
        knownIdentity: IdentityPublicKey,
        context: TypedDigest?
    ) throws -> AgentPublicKey {
        let knownSignatureBody = TBS(
            agentID: newAgentId,
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
        return try .init(archive: newAgentId)
    }
}

extension IdentityDelegate: LinearEncodedPair {
    var first: TypedKeyMaterial { newAgentId }
    var second: TypedSignature { knownIdentitySignature }

    init(first: TypedKeyMaterial, second: TypedSignature) throws {
        self.init(newAgentId: first, knownIdentitySignature: second)
    }
}

///package the elements you need for a identity handoff
public struct IdentityHandoff {
    let signedNewIdentity: SignedObject<CoreIdentity>
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
    let identityMutable: IdentityMutableData
    let newAgentKey: AgentPublicKey
    let successorSignature: TypedSignature
    let imageResource: SignedObject<Resource>

    struct Validated {
        let newIdentity: CoreIdentity
        let signedNewIdentity: SignedObject<CoreIdentity>
        let newAgentKey: AgentPublicKey
        let imageResource: Resource
    }

    func validate(
        knownIdentity: IdentityPublicKey,
        context: TypedDigest
    ) throws -> Validated {
        //verify self-contained new identity assertion
        let newIdentity = try signedNewIdentity.verifiedIdentity()

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

        //verify successor signature
        let successorSignatureBody = SuccessorTBS(
            predecessorPubKey: knownIdentity,
            context: context,
            newAgentKey: newAgentKey
        ).formatForSigning
        guard
            newIdentity.id.publicKey.isValidSignature(
                successorSignature.signature,
                for: successorSignatureBody
            )
        else {
            throw ProtocolError.authenticationError
        }

        let verfiedResource = try newAgentKey.validate(signedObject: imageResource)

        return .init(
            newIdentity: newIdentity,
            signedNewIdentity: signedNewIdentity,
            newAgentKey: newAgentKey,
            imageResource: verfiedResource
        )
    }
}

extension IdentityHandoff: LinearEncodedSextet {
    var first: SignedObject<CoreIdentity> { signedNewIdentity }
    var second: TypedSignature { predecessorSignature }
    var third: IdentityMutableData { identityMutable }
    var fourth: TypedKeyMaterial { newAgentKey.id }
    var fifth: TypedSignature { successorSignature }
    var sixth: SignedObject<Resource> { imageResource }

    init(
        first: SignedObject<CoreIdentity>,
        second: TypedSignature,
        third: IdentityMutableData,
        fourth: TypedKeyMaterial,
        fifth: TypedSignature,
        sixth: SignedObject<Resource>
    ) throws {
        self.init(
            signedNewIdentity: first,
            predecessorSignature: second,
            identityMutable: third,
            newAgentKey: try .init(archive: fourth),
            successorSignature: fifth,
            imageResource: sixth
        )
    }
}
