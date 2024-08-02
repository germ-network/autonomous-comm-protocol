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
    ) throws -> (IdentityPrivateKey, CoreIdentity, SignedObject<CoreIdentity>) {
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
            coreIdentity,
            .init(
                content: coreIdentity,
                signature: signature
            )
        )
    }

    //have to leave this framework to generate the update message
    //that we then pass to the agent in a variety of proposeAgentHandoff
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
        context: TypedDigest
    ) throws -> (AgentPrivateKey, IdentityHandoff) {
        let newAgent = AgentPrivateKey(algorithm: .curve25519)
        let newAgentPubKey = newAgent.publicKey

        let newIdentitySignatureBody = IdentityHandoff.SuccessorTBS(
            predecessorPubKey: existingIdentity,
            context: context,
            newAgentKey: newAgentPubKey
        )

        let successorSignature = try sign(input: newIdentitySignatureBody.formatForSigning)

        let handoff = IdentityHandoff(
            signedNewIdentity: signedIdentity,
            predecessorSignature: startSignature,
            newAgentKey: newAgentPubKey,
            successorSignature: successorSignature
        )

        return (newAgent, handoff)
    }

    public func sign(
        maybeMutableData: IdentityMutableData?
    ) throws -> SignedObject<IdentityMutableData>? {
        guard let mutableData = maybeMutableData else { return nil }

        return try sign(mutableData: mutableData)
    }

    public func sign(
        mutableData: IdentityMutableData
    ) throws -> SignedObject<IdentityMutableData> {
        .init(
            content: mutableData,
            signature: try sign(input: mutableData.wireFormat)
        )
        //        let encoded = try mutableData.encoded
        //
        //        return .init(
        //            signature: try sign(input: encoded),
        //            body: encoded
        //        )
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
}

public struct IdentityPublicKey: Sendable {
    let publicKey: any PublicSigningKey
    public let id: TypedKeyMaterial
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
