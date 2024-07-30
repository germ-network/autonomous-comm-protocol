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
        let coreIdentity = CoreIdentity(
            id: privateKey.publicKey,
            name: name,
            describedImage: describedImage)

        let coreIdentityData = try JSONEncoder().encode(coreIdentity)
        let signature = try privateKey.signature(for: coreIdentityData)

        return (
            privateKey,
            coreIdentity,
            .init(
                signature: signature,
                body: coreIdentityData
            )
        )
    }

    private func signature(for input: Data) throws -> TypedSignature {
        .init(
            signingAlgorithm: type(of: privateKey).signingAlgorithm,
            signature: try privateKey.signature(for: input)
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
        let signature = try signature(
            for: IdentityDelegate.TBS(
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

    public func sign(
        maybeMutableData: IdentityMutableData?
    ) throws -> SignedObject<IdentityMutableData>? {
        guard let mutableData = maybeMutableData else { return nil }

        return try sign(mutableData: mutableData)
    }

    public func sign(
        mutableData: IdentityMutableData
    ) throws -> SignedObject<IdentityMutableData> {

        let encoded = try mutableData.encoded

        return .init(
            signature: try signature(for: encoded),
            body: encoded
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
}

public struct IdentityPublicKey: Sendable {
    let publicKey: any PublicSigningKey
    public let id: TypedKeyMaterial

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

    //MARK: Validation
    public func validate(
        delegate: IdentityDelegate,
        context: TypedDigest?
    ) throws -> AgentPublicKey {
        guard
            publicKey.isValidSignature(
                delegate.knownIdentitySignature.signature,
                for: IdentityDelegate.TBS(
                    agentID: delegate.newAgentId,
                    context: context
                ).formatForSigning
            )
        else { throw ProtocolError.authenticationError }
        return try .init(archive: delegate.newAgentId)
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
