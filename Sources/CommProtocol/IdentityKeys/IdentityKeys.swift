//
//  IdentityKeys.swift
//
//
//  Created by Mark @ Germ on 6/15/24.
//

import Foundation
import CryptoKit

///- To permit cryptographic flexibility, we use 2 layers of abstraction:
/// - unify the interface in a protocol
/// - contain the protocol in a concrete object for storage
public struct IdentityPrivateKey: Sendable {
    private let privateKey: any PrivateSigningKey
    public let publicKey: IdentityPublicKey //store public key for efficiency
    
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
        let coreIdentity = CoreIdentity(id: privateKey.publicKey,
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
    
    public func agentHelloDelegate() throws -> (
        AgentPrivateKey,
        IdentityDelegate
    ) {
        let newAgent = AgentPrivateKey(algorithm: .curve25519)
        let newAgentPubKey = newAgent.publicKey
        let signature = try signature(
            for: IdentityDelegate.delegateTBS(agentKey: newAgentPubKey)
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
        case .Curve25519_Signing:
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
        case .Curve25519_Signing:
            self.init(
                concrete: try Curve25519.Signing
                    .PublicKey(rawRepresentation: archive.keyData )
            )
        default:
            throw ProtocolError.typedKeyArchiveMismatch
        }
    }
    
    //MARK: Validation
    public func validate(delegate: IdentityDelegate) throws -> AgentPublicKey {
        guard publicKey.isValidSignature(
            delegate.knownIdentitySignature.signature,
            for: delegate.delegateTBS
        ) else { throw ProtocolError.authenticationError }
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

