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
public struct AgentPrivateKey {
    private let privateKey: any PrivateSigningKey
    public let publicKey: AgentPublicKey //store public key for efficiency

    public var id: TypedKeyMaterial { publicKey.id }
    
    public init(algorithm: SigningKeyAlgorithm) {
        switch algorithm {
        case .curve25519: 
            self.privateKey = Curve25519.Signing.PrivateKey()
            self.publicKey = .init(concrete: privateKey.publicKey)
        }
    }
    
    //for local storage
    public var archive: TypedKeyMaterial { .init(typedKey: privateKey) }
    
    init(archive: TypedKeyMaterial) throws {
        switch archive.algorithm {
        case .Curve25519_Signing:
            self.init(
                concrete: try Curve25519.Signing.PrivateKey(rawRepresentation: archive.keyData)
            )
        default: throw DefinedWidthError.invalidTypedKey
        }
    }
    
    init(concrete: any PrivateSigningKey) {
        privateKey = concrete
        publicKey = .init(concrete: concrete.publicKey)
    }
    
    //MARK: signing methods
    public func sign(
        delegate: IdentityRelationshipAssertion
    ) throws -> TypedSignature {
        guard delegate.relationship == .delegateAgent,
              delegate.object == publicKey.id else {
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

}

public struct AgentPublicKey {
    private let publicKey: any PublicSigningKey
    public let id: TypedKeyMaterial
    
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
        case .Curve25519_Signing:
            self.init(
                concrete: try Curve25519.Signing
                    .PublicKey(rawRepresentation: archive.keyData )
            )
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
            throw DefinedWidthError.invalidTypedKey
        }
        
        guard let agentData = delegation.assertion.objectData else {
            throw ProtocolError.authenticationError
        }
        return try agentData.decoded()
    }
    
    public var wireFormat: Data { id.wireFormat }
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
