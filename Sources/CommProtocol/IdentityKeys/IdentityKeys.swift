//
//  IdentityKeys.swift
//
//
//  Created by Mark @ Germ on 6/15/24.
//

import CryptoKit
import Foundation

///- To permit cryptographic flexibility, we use 2 layers of abstraction:
/// - unify the interface in a protocol
/// - contain the protocol in a concrete object for storage
public struct IdentityPrivateKey: Sendable {
    private let privateKey: any PrivateSigningKey
    public let publicKey: IdentityPublicKey  //store public key for efficiency

    public var keyType: SigningKeyAlgorithm {
        type(of: privateKey).signingAlgorithm
    }

    init(algorithm: SigningKeyAlgorithm) {
        switch algorithm {
        case .curve25519:
            self.privateKey = Curve25519.Signing.PrivateKey()
            self.publicKey = .init(concrete: privateKey.publicKey)
        }
    }

    public static func create(
        name: String,
        describedImage: DescribedImage,
        algorithm: SigningKeyAlgorithm = .curve25519
    ) throws -> (IdentityPrivateKey, SignedObject<CoreIdentity>) {
        let privateKey = IdentityPrivateKey(algorithm: algorithm)
        let coreIdentity = try CoreIdentity(
            id: privateKey.publicKey,
            name: name,
            describedImage: describedImage,
            version: CoreIdentity.Constants.currentVersion,
            nonce: SymmetricKey(size: .bits128).rawRepresentation
        )

        let coreIdentityData = try coreIdentity.wireFormat
        let signature = try privateKey.sign(input: coreIdentityData)

        return (
            privateKey,
            .init(
                content: coreIdentity,
                signature: signature
            )
        )
    }

    //have to leave this framework to generate the update message
    //that we then pass to the agent in a variety of proposeAgentHandoff
    public func createHelloDelegate(
        signedIdentity: SignedObject<CoreIdentity>,
        identityMutable: IdentityMutableData,
        imageResource: Resource,
        context: TypedDigest?
    ) throws -> (
        AgentPrivateKey,
        IdentityIntroduction
    ) {
        let newAgent = AgentPrivateKey(algorithm: .curve25519)

        return (
            newAgent,
            try createIntroduction(
                signedIdentity: signedIdentity,
                newAgent: newAgent.publicKey,
                identityMutable: identityMutable,
                imageResource: imageResource,
                context: context
            )
        )
    }

    //TODO: consider deprecate?
    public func createAgentDelegate(context: TypedDigest?) throws -> (
        AgentPrivateKey,
        IdentityDelegate
    ) {
        let newAgent = AgentPrivateKey(algorithm: .curve25519)
        let newAgentPubKey = newAgent.publicKey
        let signature = try sign(
            input: IdentityDelegate.TBS(
                agentID: newAgentPubKey.id,
                context: context
            ).formatForSigning
        )
        return (
            newAgent,
            .init(
                newAgentId: newAgentPubKey.id,
                knownIdentitySignature: signature
            )
        )
    }

    ///The private keys are held in different isolation domains, so we perform this in separate
    public func startHandoff(
        to newIdentity: IdentityPublicKey,
        context: TypedDigest
    ) throws -> TypedSignature {
        let signatureBody = IdentityHandoff.PredecessorTBS(
            newIdentityPubKey: newIdentity,
            context: context
        )
        return try sign(input: signatureBody.formatForSigning)
    }

    public func createHandoff(
        existingIdentity: IdentityPublicKey,
        startSignature: TypedSignature,
        signedIdentity: SignedObject<CoreIdentity>,
        identityMutable: IdentityMutableData,
        context: TypedDigest,
        imageResource: Resource
    ) throws -> (AgentPrivateKey, IdentityHandoff) {
        let newAgent = AgentPrivateKey(algorithm: .curve25519)

        let introduction = try createIntroduction(
            signedIdentity: signedIdentity,
            newAgent: newAgent.publicKey,
            identityMutable: identityMutable,
            imageResource: imageResource,
            context: context
        )

        let handoff = IdentityHandoff(
            introduction: introduction,
            predecessorSignature: startSignature
        )

        return (newAgent, handoff)
    }

    public func sign(
        mutableData: IdentityMutableData
    ) throws -> SignedObject<IdentityMutableData> {
        .init(
            content: mutableData,
            signature: try sign(input: mutableData.wireFormat)
        )
    }

    //for local storage
    public var archive: TypedKeyMaterial { .init(typedKey: privateKey) }

    public init(archive: TypedKeyMaterial) throws {
        switch archive.algorithm {
        case .curve25519Signing:
            self.init(
                concrete: try Curve25519.Signing.PrivateKey(rawRepresentation: archive.keyData)
            )
        default: throw LinearEncodingError.invalidTypedKey
        }
    }

    init(concrete: any PrivateSigningKey) {
        privateKey = concrete
        publicKey = .init(concrete: concrete.publicKey)
    }

    //MARK: Implementation
    private func sign(input: Data) throws -> TypedSignature {
        try .init(
            prefix: keyType,
            checkedData: privateKey.signature(for: input)
        )
    }

    private func createIntroduction(
        signedIdentity: SignedObject<CoreIdentity>,
        newAgent: AgentPublicKey,
        identityMutable: IdentityMutableData,
        imageResource: Resource,
        context: TypedDigest?
    ) throws -> IdentityIntroduction {
        let introductionContent = IdentityIntroduction.Contents(
            mutableData: identityMutable,
            imageResource: imageResource,
            agentKey: newAgent
        )

        let signatureOver =
            try introductionContent
            .formatForSigning(context: context)

        return .init(
            signedIdentity: signedIdentity,
            signedContents: .init(
                content: introductionContent,
                signature: try sign(input: signatureOver)
            )
        )
    }
}

public struct IdentityPublicKey: Sendable {
    let publicKey: any PublicSigningKey
    public let id: TypedKeyMaterial

    public var wireFormat: Data { id.wireFormat }
    public var keyType: SigningKeyAlgorithm {
        type(of: publicKey).signingAlgorithm
    }

    init(concrete: any PublicSigningKey) {
        publicKey = concrete
        id = .init(typedKey: concrete)
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
    func validate<C>(signedObject: SignedObject<C>) throws -> C {
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

    func validate(signature: TypedSignature, for body: Data) throws {
        guard keyType == signature.signingAlgorithm,
            publicKey.isValidSignature(signature.signature, for: body)
        else {
            throw ProtocolError.authenticationError
        }
    }

    func validate(
        signedIntroduction: SignedObject<IdentityIntroduction.Contents>,
        context: TypedDigest?
    ) throws -> IdentityIntroduction.Contents {
        let signatureOver = try signedIntroduction.content.formatForSigning(
            context: context
        )
        guard keyType == signedIntroduction.signature.signingAlgorithm,
            publicKey.isValidSignature(
                signedIntroduction.signature.signature,
                for: signatureOver
            )
        else {
            throw ProtocolError.authenticationError
        }
        return signedIntroduction.content
    }
}

extension IdentityPublicKey: Hashable {
    //MARK: Hashable
    public func hash(into hasher: inout Hasher) {
        hasher.combine("Identity Public Key")
        hasher.combine(id)
    }
}

extension IdentityPublicKey: Equatable {
    static public func == (lhs: Self, rhs: Self) -> Bool {
        lhs.id == rhs.id
    }
}
