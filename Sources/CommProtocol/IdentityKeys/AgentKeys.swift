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

    public func sign<Content: LinearEncodable>(
        content: Content
    ) throws -> SignedObject<Content> {
        .init(
            content: content,
            signature: try sign(input: content.wireFormat)
        )
    }

    //usually implicitly authorized by the session, but need direct signing in the AgentHello
    public func sign(
        helloData: AgentHello.NewAgentData,
        for identity: IdentityPublicKey
    ) throws -> SignedObject<AgentHello.NewAgentData> {
        .init(
            content: helloData,
            signature: try sign(
                input: helloData.formatForSigning(
                    with: identity
                )
            )
        )
    }

    public func createAgentHello(
        introduction: IdentityIntroduction,
        signedAgentData: SignedObject<AgentHello.NewAgentData>
    ) throws -> AgentHello {
        .init(
            introduction: introduction,
            signedAgentData: signedAgentData)
    }

    public func createAgentHelloReply(
        introduction: IdentityIntroduction,
        agentData: AgentUpdate,
        groupIdSeed: DataIdentifier,
        welcomeMessage: Data
    ) throws -> AgentHelloReply {
        let signature = try sign(input: welcomeMessage)

        return .init(
            introduction: introduction,
            agentData: agentData,
            content: .init(
                groupIdSeed: groupIdSeed,
                agentSignatureWelcome: signature,
                seqNo: .random(in: .min...(.max)),
                sentTime: .init()
            )
        )
    }

    public func createAppWelcome(
        introduction: IdentityIntroduction,
        agentData: AgentUpdate,
        groupId: DataIdentifier,
        keyPackageData: Data
    ) throws -> AppWelcome {
        let content = AppWelcome.Content(
            groupId: groupId,
            agentData: agentData,
            seqNo: .random(in: .min...(.max)),
            sentTime: .now,
            keyPackageData: keyPackageData
        )

        let signedContent = try sign(content: content)

        return .init(
            introduction: introduction,
            signedContent: signedContent
        )
    }

    //variant when identity & agent are already known so we just need agent
    //update, and mainly sign over
    //welcome
    public func createKnownHelloReply(
        agentData: AgentUpdate,
        groupIdSeed: DataIdentifier,
        welcomeMessage: Data
    ) throws -> KnownReply {
        let signature = try sign(input: welcomeMessage)

        return .init(
            agentData: agentData,
            content: .init(
                groupIdSeed: groupIdSeed,
                agentSignatureWelcome: signature,
                seqNo: .random(in: .min...(.max)),
                sentTime: .init()
            )
        )
    }

    public func proposeLeafNode(
        leafNodeUpdate: Data,
        agentUpdate: AgentUpdate,
        signedIdentityMutable: SignedObject<IdentityMutableData>?,
        context: TypedDigest
    ) throws -> CommProposal {
        let signature = try sign(
            input: agentUpdate.formatForSigning(
                updateMessage: leafNodeUpdate,
                context: context
            )
        )

        return .sameAgent(
            .init(
                content: agentUpdate,
                signature: signature
            ),
            signedIdentityMutable
        )
    }

    ///Agent handoffs cross 2 isolation domains
    /// 1. start in IdentityPrivateKey creating a new agent
    /// 3. the new Agent completes it
    public func completeAgentHandoff(
        input: AgentHandoff.Input,
        context: TypedDigest,
        agentData: AgentUpdate,
        updateMessage: Data
    ) throws -> CommProposal {
        let newAgentSignatureOver = try AgentHandoff.NewAgentTBS(
            knownAgentKey: input.establishedAgent,
            newAgentIdentity: input.existingIdentity,
            context: context,
            updateMessage: updateMessage,
            agentData: agentData
        ).formatForSigning
        let newAgentSignature = try sign(input: newAgentSignatureOver)

        let agentHandoff = AgentHandoff(
            agentData: agentData,
            newAgentSignature: newAgentSignature
        )

        return .sameIdentity(
            input.identityDelegate,
            agentHandoff,
            input.signedIdentityMutable
        )
    }

    public func completeIdentityHandoff(
        identityHandoff: IdentityHandoff,
        establishedAgent: AgentPublicKey,
        context: TypedDigest,
        agentData: AgentUpdate,
        updateMessage: Data
    ) throws -> CommProposal {
        let newAgentSignatureOver = try AgentHandoff.NewAgentTBS(
            knownAgentKey: establishedAgent,
            newAgentIdentity: identityHandoff.introduction.signedIdentity.content.id,
            context: context,
            updateMessage: updateMessage,
            agentData: agentData
        ).formatForSigning
        let newAgentSignature = try sign(input: newAgentSignatureOver)

        let agentHandoff = AgentHandoff(
            agentData: agentData,
            newAgentSignature: newAgentSignature
        )

        return .newIdentity(identityHandoff, agentHandoff)
    }

    //MARK: Implementation
    func sign(resource: Resource) throws -> SignedObject<Resource> {
        .init(
            content: resource,
            signature: try sign(input: resource.wireFormat)
        )
    }

    private func sign(input: Data) throws -> TypedSignature {
        try .init(prefix: type, checkedData: privateKey.signature(for: input))
    }

    private func sign(
        newAgentData: AgentHello.NewAgentData,
        identity: IdentityPublicKey
    ) throws -> SignedObject<AgentHello.NewAgentData> {
        .init(
            content: newAgentData,
            signature: try sign(
                input: newAgentData.formatForSigning(
                    with: identity
                )
            )
        )
    }
}

extension AgentPrivateKey: Equatable {
    static public func == (lhs: Self, rhs: Self) -> Bool {
        lhs.id == rhs.id
    }
}

extension AgentPrivateKey: Hashable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine("Agent Private Key")
        hasher.combine(id)
    }
}

public struct AgentPublicKey: Sendable {
    let publicKey: any PublicSigningKey
    public let id: TypedKeyMaterial

    public var wireFormat: Data { id.wireFormat }
    public var keyType: SigningKeyAlgorithm {
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

    //MARK: Implementation
    public func validate<C>(signedObject: SignedObject<C>) throws -> C {
        guard keyType == signedObject.signature.signingAlgorithm,
            publicKey.isValidSignature(
                signedObject.signature.signature,
                for: try signedObject.content.wireFormat
            )
        else {
            throw ProtocolError.authenticationError
        }
        return signedObject.content
    }

    //for Hello
    func validate(
        signedAgentData: SignedObject<AgentHello.NewAgentData>,
        for identity: IdentityPublicKey
    ) throws -> AgentHello.NewAgentData {
        let signatureBody =
            try signedAgentData
            .content.formatForSigning(with: identity)
        guard keyType == signedAgentData.signature.signingAlgorithm,
            publicKey.isValidSignature(
                signedAgentData.signature.signature,
                for: signatureBody)
        else {
            throw ProtocolError.authenticationError
        }
        return signedAgentData.content
    }

    func validate(
        signedAgentUpdate: SignedObject<AgentUpdate>,
        for updateMessage: Data,
        context: TypedDigest
    ) throws -> AgentUpdate {
        let signatureBody = try signedAgentUpdate.content.formatForSigning(
            updateMessage: updateMessage,
            context: context
        )
        guard keyType == signedAgentUpdate.signature.signingAlgorithm,
            publicKey.isValidSignature(
                signedAgentUpdate.signature.signature,
                for: signatureBody)
        else {
            throw ProtocolError.authenticationError
        }
        return signedAgentUpdate.content
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
