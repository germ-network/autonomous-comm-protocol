//
//  AgentHello.swift
//
//
//  Created by Mark @ Germ on 7/2/24.
//

import CryptoKit
import Foundation

///Format for a card that gets symmetrically encrypted and exchanged
///No covering signature (just AEAD to a key directly exchanged), so all contents need to be covered by a signature
public struct AgentHello: Sendable {
    let introduction: IdentityIntroduction
    let signedAgentData: SignedObject<NewAgentData>

    //what the agent signs
    public struct NewAgentData: Sendable {
        //prepend the identity key when signing
        public let agentUpdate: AgentUpdate
        public let keyChoices: KeyPackageChoices
        public let expiration: Date

        public init(
            agentUpdate: AgentUpdate,
            keyChoices: KeyPackageChoices,
            expiration: Date
        ) {
            self.agentUpdate = agentUpdate
            self.keyChoices = keyChoices
            self.expiration = expiration
        }

        //fold in the identity key when we sign it
        func formatForSigning(
            with identityKey: IdentityPublicKey
        ) throws -> Data {
            try identityKey.id.wireFormat + wireFormat
        }
    }

    public init(
        introduction: IdentityIntroduction,
        signedAgentData: SignedObject<NewAgentData>
    ) {
        self.introduction = introduction
        self.signedAgentData = signedAgentData
    }

    public struct Validated: Sendable {
        public let coreIdentity: CoreIdentity  //from the SignedIdentity
        public let signedIdentity: SignedObject<CoreIdentity>
        public let mutableData: IdentityMutableData
        public let imageResource: Resource
        public let agentKey: AgentPublicKey
        public let agentData: NewAgentData

        init(
            coreIdentity: CoreIdentity,
            signedIdentity: SignedObject<CoreIdentity>,
            mutableData: IdentityMutableData,
            imageResource: Resource,
            agentKey: AgentPublicKey,
            agentData: NewAgentData
        ) {
            self.coreIdentity = coreIdentity
            self.signedIdentity = signedIdentity
            self.mutableData = mutableData
            self.imageResource = imageResource
            self.agentKey = agentKey
            self.agentData = agentData
        }
    }

    public func validated() throws -> Validated {
        let (identity, contents) = try introduction.validated(context: nil)

        let agentData = try contents.agentKey.validate(
            signedAgentData: signedAgentData,
            for: identity.id
        )

        return .init(
            coreIdentity: identity,
            signedIdentity: introduction.signedIdentity,
            mutableData: contents.mutableData,
            imageResource: contents.imageResource,
            agentKey: contents.agentKey,
            agentData: agentData
        )
    }
}

extension AgentHello: LinearEncodedPair {
    var first: IdentityIntroduction { introduction }
    var second: SignedObject<NewAgentData> { signedAgentData }

    init(
        first: IdentityIntroduction,
        second: SignedObject<NewAgentData>
    ) throws {
        self.init(
            introduction: first,
            signedAgentData: second
        )
    }
}

extension AgentHello.NewAgentData: LinearEncodedTriple {
    var first: AgentUpdate { agentUpdate }
    var second: KeyPackageChoices { keyChoices }
    var third: Date { expiration }

    init(
        first: AgentUpdate,
        second: [TypedKeyPackage],
        third: Date
    ) throws {
        self.init(
            agentUpdate: first,
            keyChoices: second,
            expiration: third
        )
    }
}

//mainly for testability
extension AgentHello.NewAgentData: Equatable {}
