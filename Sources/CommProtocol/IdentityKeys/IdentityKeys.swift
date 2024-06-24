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
public struct IdentityPrivateKey: Codable, Sendable {
    private let privateKey: any PrivateSigningKey
    public var publicKey: IdentityPublicKey //store public key for efficiency
    
    private init(algorithm: SigningKeyAlgorithm) throws {
        switch algorithm {
        case .curve25519:
            let (privateKey, publicKey) = Curve25519.Signing.PrivateKey.newKeyPair()
            self.privateKey = privateKey
            self.publicKey = try .init(concrete: publicKey)
        }
    }
    
    public static func create(
        name: String,
        describedImage: DescribedImage,
        algorithm: SigningKeyAlgorithm = .curve25519
    ) throws -> (IdentityPrivateKey, CoreIdentity, SignedIdentity) {
        let privateKey = try IdentityPrivateKey(algorithm: algorithm)
        let coreIdentity = CoreIdentity(id: privateKey.publicKey,
                                        name: name,
                                        describedImage: describedImage)
        
        let coreIdentityData = try JSONEncoder().encode(coreIdentity)
        let coreIdentityDigest = SHA256.hash(data: coreIdentityData)
        let identityAssertionData = try IdentityAssertion(
            digest: coreIdentityDigest.data
        ).encoded
        
        let signature = try privateKey.signature(for: identityAssertionData)
        
        return (
            privateKey,
            coreIdentity,
            .init(credentialData: coreIdentityData,
                  signedDigest: .init(body: coreIdentityDigest.data,
                                      signature: signature))
            
        )
    }
    
    private func signature(for input: Data) throws -> Data {
        try privateKey.signature(for: input)
    }
    
    //MARK: Codable
    private var archive: TypedKeyMaterial {
        get throws {
            try .init(typedKey: privateKey)
        }
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let archive = try container.decode(Data.self)
        let typedArchive: TypedKeyMaterial = try .init(wireformat: archive)
        
        switch typedArchive.algorithm {
        case .Curve25519_Signing:
            privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: typedArchive.keyData)
            publicKey = try .init(concrete: privateKey.publicKey)
        default: throw ProtocolError.typedKeyArchiveMismatch
        }
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(archive.wireFormat)
    }
}

public struct IdentityPublicKey: Codable, Sendable, Hashable {
    private let publicKey: any PublicSigningKey
    private let typedKey: TypedKeyMaterial
    
    init(concrete: any PublicSigningKey) throws {
        publicKey = concrete
        typedKey = try .init(typedKey: concrete)
    }
    
    var id: Data {
        typedKey.wireFormat
    }
    
    public init(wireFormat: Data) throws {
        typedKey = try TypedKeyMaterial(wireformat: wireFormat)
        
        switch typedKey.algorithm {
        case .Curve25519_Signing: publicKey = try Curve25519.Signing
                .PublicKey(rawRepresentation: typedKey.keyData )
        default:
            throw ProtocolError.typedKeyArchiveMismatch
        }
    }
    
    public var wireFormat: Data {
        get throws {
            try archive.wireFormat
        }
    }
    
    //MARK: Methods
    public func validate(
        signedDigest: SignedObject<IdentityAssertion>
    ) throws -> IdentityAssertion {
        guard publicKey.isValidSignature(signedDigest.signature,
                                         for: signedDigest.body) else {
            throw ProtocolError.authenticationError
        }
        return try signedDigest.body.decoded()
    }
    
    //MARK: Codable
    public var archive: TypedKeyMaterial {
        get throws {
            try .init(typedKey: publicKey)
        }
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let archive = try container.decode(Data.self)
        let typedArchive: TypedKeyMaterial = try .init(wireformat: archive)
        
        switch typedArchive.algorithm {
        case .Curve25519_Signing:
            publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: typedArchive.keyData)
            typedKey = try .init(typedKey: publicKey)
        default: throw ProtocolError.typedKeyArchiveMismatch
        }
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(archive.wireFormat)
    }
    
    //MARK: Hashable
    public func hash(into hasher: inout Hasher) {
        hasher.combine(publicKey.hashValue)
    }
}

extension IdentityPublicKey: Equatable {
    static public func == (lhs: Self, rhs: Self) -> Bool {
        do {
            return try lhs.archive == rhs.archive
        } catch {
            return false
        }
    }
}

