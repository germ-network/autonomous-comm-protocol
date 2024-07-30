//
//  AgentHello.swift
//
//
//  Created by Mark @ Germ on 7/2/24.
//

import CryptoKit
import Foundation

///Format for a card that gets symmetrically encrypted and exchanged
public struct AgentHello: Sendable {
    //Identity
    public let signedIdentity: SignedObject<CoreIdentity>
    public let identityMutable: SignedObject<IdentityMutableData>

    //Agent
    public let agentDelegate: IdentityDelegate
    public let agentSignedData: Data  //AgentTBS encoded
    public let agentSignature: Data

    //what the agent signs
    public struct AgentTBS: Codable, Sendable {
        //prepend the identity key when signing
        public let version: SemanticVersion
        public let isAppClip: Bool?  //ommitted when false
        public let addresses: [ProtocolAddress]
        public let keyChoices: KeyPackageChoices
        public let imageResource: Resource?
        public let expiration: Date
    }

    init(
        signedIdentity: SignedObject<CoreIdentity>,
        identityMutable: SignedObject<IdentityMutableData>,
        agentDelegate: IdentityDelegate,
        agentSignedData: Data,
        agentSignature: Data  //bare signature, not typed signature
    ) {
        self.signedIdentity = signedIdentity
        self.identityMutable = identityMutable
        self.agentDelegate = agentDelegate
        self.agentSignedData = agentSignedData
        self.agentSignature = agentSignature
    }

    public struct Validated: Sendable {
        public let coreIdentity: CoreIdentity  //from the SignedIdentity
        public let signedIdentity: SignedObject<CoreIdentity>
        public let mutableData: IdentityMutableData
        public let agentKey: AgentPublicKey
        public let agentData: AgentTBS

        init(
            coreIdentity: CoreIdentity, signedIdentity: SignedObject<CoreIdentity>,
            mutableData: IdentityMutableData, agentKey: AgentPublicKey, agentData: AgentTBS
        ) {
            self.coreIdentity = coreIdentity
            self.signedIdentity = signedIdentity
            self.mutableData = mutableData
            self.agentKey = agentKey
            self.agentData = agentData
        }
    }

    public func validated() throws -> Validated {
        let identity = try signedIdentity.verifiedIdentity()
        let identityKey = try IdentityPublicKey(wireFormat: identity.id)
        let agentKey = try identityKey.validate(
            delegate: agentDelegate,
            context: nil
        )

        guard
            agentKey.publicKey.isValidSignature(
                agentSignature,
                for: identityKey.id.wireFormat + agentSignedData
            )
        else { throw ProtocolError.authenticationError }

        return .init(
            coreIdentity: identity,
            signedIdentity: signedIdentity,
            mutableData: try identityMutable.validate(for: identityKey.publicKey),
            agentKey: agentKey,
            agentData: try agentSignedData.decoded()
        )
    }
}

extension AgentHello: Codable {
    public enum CodingKeys: CodingKey {
        case signedIdentity, identityMutable, agentDelegate, agentSignedData, agentSignature
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.signedIdentity = try .init(
            wireFormat: values.decode(Data.self, forKey: .signedIdentity)
        )
        self.identityMutable = try .init(
            wireFormat: values.decode(Data.self, forKey: .identityMutable)
        )
        //will deprecate
        let stored = try values.decode(Data.self, forKey: .agentDelegate)
        self.agentDelegate = try IdentityDelegate.finalParse(stored)
        self.agentSignedData = try values.decode(
            Data.self,
            forKey: .agentSignedData)
        self.agentSignature = try values.decode(
            Data.self,
            forKey: .agentSignature)

    }

    public func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(signedIdentity.wireFormat, forKey: .signedIdentity)
        try values.encode(identityMutable.wireFormat, forKey: .identityMutable)
        try values.encode(agentDelegate.wireFormat, forKey: .agentDelegate)
        try values.encode(agentSignedData, forKey: .agentSignedData)
        try values.encode(agentSignature, forKey: .agentSignature)
    }
}

//mainly for testability
extension AgentHello.AgentTBS: Equatable {}

// public struct AgentHelloReply: Codable, Sendable {
// }
