//
//  Agents.swift
//
//
//  Created by Mark Xue on 6/12/24.
//

import Foundation
import CryptoKit

///- To permit cryptographic flexibility, we
/// - contain signing keys in an abstract protocol
/// - use a concrete roled type that contains a type conforming to the signing key protocol

//MARK: Concrete object
public struct AgentPrivateKey: Codable {
    private let privateKey: any PrivateSigningKey
    private let storedPublicKey: any PublicSigningKey //store public key for efficiency
    
    public var publicKey: AgentPublicKey {
        .init(concrete: storedPublicKey)
    }

    public var id: Data { storedPublicKey.rawRepresentation }
    
    public init(algorithm: SigningKeyAlgorithm) {
        switch algorithm {
        case .curve25519: 
            (self.privateKey, self.storedPublicKey) = Curve25519.Signing.PrivateKey.newKeyPair()
        }
    }
    
    init(concrete: any PrivateSigningKey) {
        privateKey = concrete
        storedPublicKey = concrete.publicKey
    }
    
    //MARK: signing methods
    public func sign(
        delegate: IdentityRelationshipAssertion
    ) throws -> TypedSignature {
        let myKey = try publicKey.archive
        guard delegate.relationship == .delegateAgent,
              delegate.object == myKey else {
            throw ProtocolError.signatureDisallowed
        }
        return .init(
            signingAlgorithm: type(of: privateKey).signingAlgorithm,
            signature: try privateKey.signature(for: delegate.wireFormat)
        )
    }
    
    //    public func sign(resource: Resource)
    //    throws -> SignedObject<Resource> {
    //        let data = try resource.encoded
    //        let signature = try key.signature(for: data)
    //        return .init(body: data, signature: signature)
    //    }
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
    //    //still used for legacy actor, which sends the complete signed address
    //    public func sign(addresses: [ProtocolAddress]) throws -> CompleteSignedObject<AddressBody> {
    //        let data = try AddressBody(addresses: addresses).encoded
    //        let signature = try key.signature(for: data)
    //        return .init(body: data,
    //                     signature: signature,
    //                     signerArchive: publicTypedKey.stablePublicArchive)
    //    }
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
    
    //MARK: Codable
    private var archive: TypedKeyMaterial {
        get throws {
            try .init(typedKey: privateKey)
        }
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let archive = try container.decode(Data.self)
        let typedArchive: TypedKeyMaterial = try .init(wireFormat: archive)
        
        switch typedArchive.algorithm {
        case .Curve25519_Signing:
            privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: typedArchive.keyData)
            storedPublicKey = privateKey.publicKey
        default: throw ProtocolError.typedKeyArchiveMismatch
        }
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(archive.wireFormat)
    }
}

public struct AgentPublicKey: Codable {
    private let publicKey: any PublicSigningKey
    
    public var id: Data { publicKey.rawRepresentation }
    
    init(concrete: any PublicSigningKey) {
        publicKey = concrete
    }
    
    public init(wireFormat: Data) throws {
        let typedArchive = try TypedKeyMaterial(wireFormat: wireFormat)
        
        try self.init(archive: typedArchive)
    }
    
    public init(archive: TypedKeyMaterial) throws {
        switch archive.algorithm {
        case .Curve25519_Signing: publicKey = try Curve25519.Signing
                .PublicKey(rawRepresentation: archive.keyData )
        default:
            throw ProtocolError.typedKeyArchiveMismatch
        }
    }
    
    //presume subject (identity) key will separately verify
    public func validate(
        delegation: SignedIdentityRelationship
    ) throws -> AgentData {
        guard delegation.subjectSignature.signingAlgorithm == type(of: publicKey).signingAlgorithm,
            publicKey.isValidSignature(
                delegation.objectSignature.signature,
            for: delegation.assertion.wireFormat
        ) else {
            throw TypedKeyError.invalidTypedKey
        }
        
        guard let agentData = delegation.assertion.objectData else {
            throw ProtocolError.authenticationError
        }
        return try agentData.decoded()
    }
    
    public var wireFormat: Data {
        get throws {
            try archive.wireFormat
        }
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
        let typedArchive: TypedKeyMaterial = try .init(wireFormat: archive)
        
        switch typedArchive.algorithm {
        case .Curve25519_Signing:
            publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: typedArchive.keyData)
        default: throw ProtocolError.typedKeyArchiveMismatch
        }
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(archive.wireFormat)
    }
}

extension AgentPublicKey: Equatable {
    static public func == (lhs: Self, rhs: Self) -> Bool {
        type(of: lhs.publicKey).signingAlgorithm == type(of: rhs.publicKey).signingAlgorithm
        && lhs.id == rhs.id
    }
}
