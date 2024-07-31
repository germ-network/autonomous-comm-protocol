//
//  Agents.swift
//
//
//  Created by Mark Xue on 6/12/24.
//

import CryptoKit
import Foundation

///- To permit cryptographic flexibility, we
/// - contain signing keys in an abstract protocol
/// - use a concrete roled type that contains a type conforming to the signing key protocol

//MARK: Concrete object
public struct AgentPrivateKey: Sendable {
    private let privateKey: any PrivateSigningKey
    public let publicKey: AgentPublicKey  //store public key for efficiency

    public var id: TypedKeyMaterial { publicKey.id }
    public var type: SigningKeyAlgorithm {
        Swift.type(of: privateKey).signingAlgorithm
    }

    public init(algorithm: SigningKeyAlgorithm) {
        switch algorithm {
        case .curve25519:
            self.privateKey = Curve25519.Signing.PrivateKey()
            self.publicKey = .init(concrete: privateKey.publicKey)
        }
    }

    //for local storage
    public var archive: TypedKeyMaterial { .init(typedKey: privateKey) }

    public init(archive: TypedKeyMaterial) throws {
        switch archive.algorithm {
        case .curve25519Signing:
            self.init(
                concrete: try Curve25519.Signing.PrivateKey(rawRepresentation: archive.keyData)
            )
        default: throw ProtocolError.typedKeyArchiveMismatch
        }
    }

    init(concrete: any PrivateSigningKey) {
        privateKey = concrete
        publicKey = .init(concrete: concrete.publicKey)
    }

    public func createAgentHello(
        signedIdentity: SignedIdentity,
        identityMutable: SignedObject<IdentityMutableData>,
        agentDelegate: IdentityDelegate,
        agentTBS: AgentHello.AgentTBS
    ) throws -> AgentHello {
        let identityKey = try signedIdentity.verifiedIdentity().id

        let encodedTBS = try agentTBS.encoded
        let signature = try privateKey.signature(
            for: identityKey.id.wireFormat + encodedTBS
        )

        return .init(
            signedIdentity: signedIdentity,
            identityMutable: identityMutable,
            agentDelegate: agentDelegate,
            agentSignedData: encodedTBS,
            agentSignature: signature
        )
    }

    public func proposeLeafNode(update: Data) throws -> CommProposal {
        let signature = try privateKey.signature(for: update)
        let typedSignature: TypedSignature = .init(
            signingAlgorithm: type,
            signature: signature
        )
        return .sameAgent(typedSignature)
    }

    ///Agent handoffs cross 3 isolation domains
    /// 1. start in IdentityPrivateKey creating a new agent
    /// 2. the existing Agent signs the new agent Key
    /// 3. the new Agent completes it
    public func startAgentHandoff(
        newAgent: AgentPublicKey,
        context: TypedDigest
    ) throws -> TypedSignature {
        let signatureOver = AgentHandoff.KnownAgentTBS(
            newAgentKey: newAgent,
            context: context
        )
        return try sign(input: signatureOver.formatForSigning)
    }

    public func completeAgentHandoff(
        existingIdentity: IdentityPublicKey,
        identityDelegate: IdentityDelegate,
        establishedAgent: AgentPublicKey,
        establishedSignature: TypedSignature,
        context: TypedDigest,
        agentData: AgentUpdate,
        updateMessage: Data
    ) throws -> CommProposal {
        let encodedAgentData = try agentData.encoded

        let newAgentSignatureOver = AgentHandoff.NewAgentTBS(
            knownAgentKey: establishedAgent,
            newAgentIdentity: existingIdentity,
            context: context,
            agentData: encodedAgentData,
            updateMessage: updateMessage
        ).formatForSigning
        let newAgentSignature = try sign(input: newAgentSignatureOver)

        let agentHandoff = AgentHandoff(
            knownAgentSignature: establishedSignature,
            encodedAgentData: try .init(body: encodedAgentData),
            newAgentSignature: newAgentSignature
        )

        return .sameIdentity(identityDelegate, agentHandoff)
    }

    public func completeIdentityHandoff(
        newIdentity: IdentityPublicKey,
        identityHandoff: IdentityHandoff,
        establishedAgent: AgentPublicKey,
        establishedAgentSignature: TypedSignature,
        context: TypedDigest,
        agentData: AgentUpdate,
        updateMessage: Data
    ) throws -> CommProposal {
        let encodedAgentData = try agentData.encoded

        let newAgentSignatureOver = AgentHandoff.NewAgentTBS(
            knownAgentKey: establishedAgent,
            newAgentIdentity: newIdentity,
            context: context,
            agentData: encodedAgentData,
            updateMessage: updateMessage
        ).formatForSigning
        let newAgentSignature = try sign(input: newAgentSignatureOver)

        let agentHandoff = AgentHandoff(
            knownAgentSignature: establishedAgentSignature,
            encodedAgentData: try .init(body: encodedAgentData),
            newAgentSignature: newAgentSignature
        )

        return .newIdentity(identityHandoff, agentHandoff)
    }

    //MARK: Implementation
    private func sign(input: Data) throws -> TypedSignature {
        try .init(prefix: type, checkedData: privateKey.signature(for: input))
    }

    //
    //    public func sign(transition: SignedAgentTransition.Transition)
    //    throws -> (encoded: Data, signature: Data) {
    //        let encoded = try transition.encoded
    //        return (encoded: encoded, signature: try key.signature(for: encoded))
    //    }
    //
    //    public func sign(helloReply: HelloReply) throws -> SignedObject<HelloReply> {
    //        let data = try helloReply.encoded
    //        let signature = try key.signature(for: data)
    //        return .init(body: data,
    //                     signature: signature)
    //    }
    //

    //
    //    public func sign(preSessionMap: TypedPreSessionMap) throws -> SignedObject<TypedPreSessionMap> {
    //        let data = try preSessionMap.encoded
    //        let signature = try key.signature(for: data)
    //        return .init(body: data,
    //                     signature: signature)
    //    }
    //
    //    //unused, retain until we determine if we will generate legacy invitations
    //    public func sign(sessionInvitation: TypedSessionInvitation) throws -> CompleteSignedObject<TypedSessionInvitation> {
    //        let data = try sessionInvitation.encoded
    //        let signature = try key.signature(for: data)
    //        return .init(body: data,
    //                     signature: signature,
    //                     signerArchive: publicTypedKey.stablePublicArchive)
    //    }

}

public struct AgentPublicKey: Sendable {
    let publicKey: any PublicSigningKey
    public let id: TypedKeyMaterial

    public var wireFormat: Data { id.wireFormat }
    public var type: SigningKeyAlgorithm {
        Swift.type(of: publicKey).signingAlgorithm
    }

    init(concrete: any PublicSigningKey) {
        publicKey = concrete
        id = .init(typedKey: publicKey)
    }

    public init(wireFormat: Data) throws {
        let typedArchive = try TypedKeyMaterial(wireFormat: wireFormat)
        try self.init(archive: typedArchive)
    }

    public init(archive: TypedKeyMaterial) throws {
        switch archive.algorithm {
        case .curve25519Signing:
            self.init(
                concrete: try Curve25519.Signing
                    .PublicKey(rawRepresentation: archive.keyData)
            )
        default:
            throw ProtocolError.typedKeyArchiveMismatch
        }
    }

    //Deprecate?
    //presume subject (identity) key will separately verify

    func validate<T>(
        signedObject: SignedObject<T>
    ) throws -> T where T: SignableObject, T: Codable {
        guard T.type.signer == .agent else {
            throw ProtocolError.incorrectSigner
        }
        return try JSONDecoder().decode(
            T.self,
            from: signedObject.validate(for: publicKey)
        )
    }

    func validate<T>(
        signedObject: SignedObject<T>?
    ) throws -> T? where T: SignableObject, T: Codable {
        guard let signedObject else { return nil }
        guard T.type.signer == .agent else {
            throw ProtocolError.incorrectSigner
        }
        return try JSONDecoder().decode(
            T.self,
            from: signedObject.validate(for: publicKey)
        )
    }

}

extension AgentPublicKey: Hashable {
    //MARK: Hashable
    public func hash(into hasher: inout Hasher) {
        hasher.combine("Agent Public Key")
        hasher.combine(id)
    }
}

extension AgentPublicKey: Equatable {
    static public func == (lhs: Self, rhs: Self) -> Bool {
        lhs.id == rhs.id
    }
}

extension AgentPublicKey: WireFormat {}
