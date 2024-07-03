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
    
    private init(algorithm: SigningKeyAlgorithm) throws {
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
    ) throws -> (IdentityPrivateKey, CoreIdentity, SignedIdentity) {
        let privateKey = try IdentityPrivateKey(algorithm: algorithm)
        let coreIdentity = CoreIdentity(id: privateKey.publicKey,
                                        name: name,
                                        describedImage: describedImage)
        
        let coreIdentityData = try JSONEncoder().encode(coreIdentity)
        let coreIdentityDigest = SHA256.hash(data: coreIdentityData)
        let identityAssertionData = IdentityAssertion(
            hashAlgorithm: .sha256,
            digest: coreIdentityDigest.data
        ).wireFormat
        
        let signature = try privateKey.signature(for: identityAssertionData)
        
        return (
            privateKey,
            coreIdentity,
            .init(
                signedDigest: .init(bodyType: .identityDigest,
                                    signature: signature,
                                    body: coreIdentityDigest.data),
                identityData: coreIdentityData
            )
        )
    }
    
    private func signature(for input: Data) throws -> TypedSignature {
        .init(
            signingAlgorithm: type(of: privateKey).signingAlgorithm,
            signature: try privateKey.signature(for: input)
        )
    }
    
    public func delegate(
        agentData: AgentData
    ) throws -> (AgentPrivateKey, SignedIdentityRelationship) {
        let newAgent = AgentPrivateKey(algorithm: .curve25519)
        
        let assertion = IdentityRelationshipAssertion(
            relationship: .delegateAgent,
            subject: publicKey.id,
            object: newAgent.publicKey.id,
            objectData: try agentData.encoded
        )
        let assertionData = assertion.wireFormat
        let subjectSignature = try signature(for: assertionData)
        let objectSignature = try newAgent.sign(delegate: assertion)
        
        return (
            newAgent,
            .init(
                subjectSignature: subjectSignature,
                objectSignature: objectSignature,
                assertion: assertion
            )
        )
    }
    
    public func sign(
        mutableData: IdentityMutableData?
    ) throws -> SignedObject<IdentityMutableData>? {
        guard let mutableData else { return nil }
        guard mutableData.identityPublicKeyData == publicKey.id.wireFormat else {
            throw ProtocolError.incorrectSigner
        }
        
        let encoded = try mutableData.encoded
        
        return .init(
            bodyType: .identityMutableData,
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
        default: throw DefinedWidthError.invalidTypedKey
        }
    }
    
    init(concrete: any PrivateSigningKey) {
        privateKey = concrete
        publicKey = .init(concrete: concrete.publicKey)
    }
}

public struct IdentityPublicKey: Sendable {
    private let publicKey: any PublicSigningKey
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
    
    //MARK: Methods
    public func validate(
        signedDigest: SignedObject<IdentityAssertion>
    ) throws -> IdentityAssertion {
        try signedDigest.validate(for: publicKey)
    }
    
    public func validate(
        delegation: SignedIdentityRelationship
    ) throws -> (AgentPublicKey, AgentData) {
        //check subject signature
        guard delegation.subjectSignature.signingAlgorithm == type(of: publicKey).signingAlgorithm,
              publicKey.isValidSignature(
                delegation.subjectSignature.signature,
                for: delegation.assertion.wireFormat
              )
        else {
            throw ProtocolError.authenticationError
        }
        
        //then examine the assertion
        guard delegation.assertion.relationship == .delegateAgent,
              delegation.assertion.subject == id else {
            throw ProtocolError.authenticationError
        }
        let assertedObject = try AgentPublicKey(archive: delegation.assertion.object)
        
        //check it concurs:
        let data = try assertedObject.validate(delegation: delegation)
        return (assertedObject, data)
    }
    
    func validate(
        signedMutableData: SignedObject<IdentityMutableData>?
    ) throws -> IdentityMutableData? {
        guard let signedMutableData else { return nil }
        return try JSONDecoder().decode(
            IdentityMutableData.self,
            from: signedMutableData.validate(for: publicKey)
        )
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

