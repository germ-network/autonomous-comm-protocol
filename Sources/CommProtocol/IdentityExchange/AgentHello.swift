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
    //Identity
    let signedIdentity: SignedObject<CoreIdentity>
    let identityMutable: SignedObject<IdentityMutableData>

    //Agent
    let agentDelegate: IdentityDelegate
    let signedAgentData: SignedObject<NewAgentData>

    //what the agent signs
    public struct NewAgentData: Sendable {
        //prepend the identity key when signing
        public let version: SemanticVersion
        public let isAppClip: Bool
        public let addresses: [ProtocolAddress]
        public let keyChoices: KeyPackageChoices
        public let imageResource: Resource
        public let expiration: Date

        public init(
            version: SemanticVersion,
            isAppClip: Bool,
            addresses: [ProtocolAddress],
            keyChoices: KeyPackageChoices,
            imageResource: Resource,
            expiration: Date
        ) {
            self.version = version
            self.isAppClip = isAppClip
            self.addresses = addresses
            self.keyChoices = keyChoices
            self.imageResource = imageResource
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
        signedIdentity: SignedObject<CoreIdentity>,
        identityMutable: SignedObject<IdentityMutableData>,
        agentDelegate: IdentityDelegate,
        signedAgentData: SignedObject<NewAgentData>
    ) {
        self.signedIdentity = signedIdentity
        self.identityMutable = identityMutable
        self.agentDelegate = agentDelegate
        self.signedAgentData = signedAgentData
    }

    public struct Validated: Sendable {
        public let coreIdentity: CoreIdentity  //from the SignedIdentity
        public let signedIdentity: SignedObject<CoreIdentity>
        public let mutableData: IdentityMutableData
        public let agentKey: AgentPublicKey
        public let agentData: NewAgentData

        init(
            coreIdentity: CoreIdentity,
            signedIdentity: SignedObject<CoreIdentity>,
            mutableData: IdentityMutableData,
            agentKey: AgentPublicKey,
            agentData: NewAgentData
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
        let identityKey = identity.id
        let agentKey = try agentDelegate.validate(
            knownIdentity: identityKey,
            context: nil
        )

        let agentData = try agentKey.validate(
            signedAgentData: signedAgentData,
            for: identityKey
        )

        return .init(
            coreIdentity: identity,
            signedIdentity: signedIdentity,
            mutableData: try identityKey.validate(signedObject: identityMutable),
            agentKey: agentKey,
            agentData: agentData
        )
    }
}

extension AgentHello: LinearEncodable {
    public static func parse(_ input: Data) throws -> (AgentHello, Int) {
        let (
            signedIdentity,
            identityMutable,
            agentDelegate,
            signedAgentData,
            consumed
        ) = try LinearEncoder.decode(
            SignedObject<CoreIdentity>.self,
            SignedObject<IdentityMutableData>.self,
            IdentityDelegate.self,
            SignedObject<NewAgentData>.self,
            input: input
        )

        let result = AgentHello(
            signedIdentity: signedIdentity,
            identityMutable: identityMutable,
            agentDelegate: agentDelegate,
            signedAgentData: signedAgentData
        )
        return (result, consumed)
    }

    public var wireFormat: Data {
        get throws {
            try signedIdentity.wireFormat
                + identityMutable.wireFormat
                + agentDelegate.wireFormat
                + signedAgentData.wireFormat
        }
    }
}

extension AgentHello.NewAgentData: LinearEncodable {
    public static func parse(_ input: Data) throws -> (
        AgentHello.NewAgentData,
        Int
    ) {
        let (
            version,
            isAppClip,
            addresses,
            keyChoices,
            imageResource,
            expiration,
            consumed
        ) = try LinearEncoder.decode(
            SemanticVersion.self,
            Bool.self,
            [ProtocolAddress].self,
            KeyPackageChoices.self,
            Resource.self,
            Date.self,
            input: input
        )

        let result = Self(
            version: version,
            isAppClip: isAppClip,
            addresses: addresses,
            keyChoices: keyChoices,
            imageResource: imageResource,
            expiration: expiration
        )

        return (result, consumed)
    }

    public var wireFormat: Data {
        get throws {
            try version.wireFormat
                + isAppClip.wireFormat
                + addresses.wireFormat
                + keyChoices.wireFormat
                + imageResource.wireFormat
                + expiration.wireFormat
        }
    }
}

//mainly for testability
extension AgentHello.NewAgentData: Equatable {}
