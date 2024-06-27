//
//  File.swift
//  
//
//  Created by Mark @ Germ on 6/15/24.
//

import Foundation
import CryptoKit

///CoreIdentity is an identity key that asserts a user-facing representation:
/// - name (assert once)
/// - image (hash, assert once)
/// - pronouns
/// - bindings to other identities
///
public struct CoreIdentity: Codable, Sendable {
    struct Constants {
        //previously, 0.0.1
        static let currentVersion = SemanticVersion(major: 1, minor: 0, patch: 0)
    }
    
    public let id: Data //WireFormat for IdentityPublicKey
    public let name: String
    public let describedImage: DescribedImage
    public let version: SemanticVersion
    public let nonce: Data
    
    init(id: IdentityPublicKey, name: String, describedImage: DescribedImage) {
        self.id = id.id.wireFormat
        self.name = name
        self.describedImage = describedImage
        self.version = Constants.currentVersion
        self.nonce = SymmetricKey(size: .bits128).rawRepresentation
    }
}

public struct DescribedImage: Equatable, Codable, Sendable{
    public let imageDigest: Data
    public let altText: String?
    
    public init(imageDigest: Data, altText: String?) {
        self.imageDigest = imageDigest
        self.altText = altText
    }
}

//MARK: Signed identity
///Bundles the encoded CoreIdentity
///The CoreIdentity contains two variable-length strings, and we expect it to grow, so we leave it JSON-encoded for flexibility
///Because JSON encoding does not produce a stable output, we have to store and exchange the particular encoding that we sign
///
///However, since signedDigest is a predictable width, we can be a bit more efficient by leaving the signedDigest
///in raw bytes and not base64 encoding it
public struct SignedIdentity: WireFormat, Sendable {
    public let signedDigest: SignedObject<IdentityAssertion>
    public let credentialData: Data
    
    public var wireFormat: Data {
        signedDigest.wireFormat + credentialData
    }
    
    init(signedDigest: SignedObject<IdentityAssertion>, credentialData: Data) {
        self.signedDigest = signedDigest
        self.credentialData = credentialData
    }
    
    public init(wireFormat: Data) throws {
        let (signedObjectType, signature, suffix) = try SignedObject<IdentityAssertion>.parse(
            wireFormat: wireFormat
        )
        guard signedObjectType == .identityDigest else {
            throw ProtocolError.authenticationError
        }
        let (identityAssertion, credentialData) = try IdentityAssertion
            .parse(wireFormat: suffix)
        guard let credentialData else { throw ProtocolError.authenticationError }
        
        signedDigest = .init(bodyType: signedObjectType,
                             signature: signature,
                             body: identityAssertion.wireFormat)
        self.credentialData = credentialData
    }
    
    public func verifiedIdentity() throws -> CoreIdentity {
        //have to decode the credentialData to get the public key
        let coreIdentity: CoreIdentity = try credentialData.decoded()
        
        //remainder of credential is not valid until we validate the signature
        let identityKey: IdentityPublicKey = try .init(wireFormat: coreIdentity.id)
        let identityDigest = try identityKey.validate(signedDigest: signedDigest)
        
        guard SHA256.hash(data: credentialData).data == identityDigest.digest else {
            throw ProtocolError.mismatchedDigest
        }
            
        return coreIdentity
    }
}

//sign the digest
public struct IdentityAssertion: SignableObject, DefinedWidthBinary {
    public typealias Prefix = HashAlgorithms
    public static let type: SignableObjectTypes = .identityDigest

    public let hashAlgorithm: HashAlgorithms
    public let digest: Data
    
    public var wireFormat: Data {
        [hashAlgorithm.rawValue] + digest
    }
    
    public init(prefix: Prefix, checkedData: Data) throws {
        guard prefix.contentByteSize == checkedData.count else {
            throw DefinedWidthError.incorrectDataLength
        }
        self.init(hashAlgorithm: prefix, digest: checkedData)
    }
    
    init(hashAlgorithm: HashAlgorithms, digest: Data) {
        self.hashAlgorithm = hashAlgorithm
        self.digest = digest
    }
}

public enum HashAlgorithms: UInt8, DefinedWidthPrefix {
    case sha256 //RFC 6234
    
    public var contentByteSize: Int { digestWidth }
    
    private var digestWidth: Int {
        switch self {
        case .sha256: 32
        }
    }
}

public struct IdentityMutableData: SignableObject, Codable, Sendable{
    public static var type: SignableObjectTypes = .identityMutableData
    public var type: SignableObjectTypes = .identityMutableData
    public let counter: UInt16 //for predecence defined by the sender/signer
    public let identityPublicKeyData: Data //wireformat of the identity public key
    public let pronouns: [String]?
    public let aboutText: String?
}
