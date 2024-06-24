//
//  File.swift
//  
//
//  Created by Mark @ Germ on 6/15/24.
//

import Foundation
import CryptoKit

/*
CoreIdentity keys are bound to card associated data at creation time (name, image, recovery, etc)
 This object stores all the associated data as a signed object:
 [CardAssociatedData][KeyPackage][Signature over the previous two]
 
  - A digest of [CardAssociatedData][KeyPackage] + Singature are stored along with the keys in keychain
  -  this full data representation is stored in Core Data and decoded on access
 */

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
    
    public let id: IdentityPublicKey
    public let name: String
    public let describedImage: DescribedImage
    public let version: SemanticVersion
    public let nonce: Data
    
    init(id: IdentityPublicKey, name: String, describedImage: DescribedImage) {
        self.id = id
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
//sign the digest
public struct IdentityAssertion: SignableObject {
    public static let type: SignableObjectTypes = .identityDigest
    public var type: SignableObjectTypes = .identityDigest
    public let digest: Data
}

///Bundles the encoded CoreIdentity
public struct SignedIdentity: Codable, Sendable {
    public let credentialData: Data
    public let signedDigest: SignedObject<IdentityAssertion>
    
    public func verifiedIdentity() throws -> CoreIdentity {
        //have to decode the credentialData to get the public key
        let coreIdentity: CoreIdentity = try credentialData.decoded()
        
        //remainder of credential is not valid until we validate the signature
        let identityDigest = try coreIdentity.id.validate(signedDigest: signedDigest)
        
        guard SHA256.hash(data: credentialData).data == identityDigest.digest else {
            throw ProtocolError.mismatchedDigest
        }
            
        return coreIdentity
    }
}

public struct IdentityMutableData: SignableObject, Sendable{
    public static var type: SignableObjectTypes = .identityMutableData
    public var type: SignableObjectTypes = .identityMutableData
    public let counter: UInt16 //for predecence defined by the sender/signer
    public let identityPublicKey: IdentityPublicKey //identifier of the core card this updates/is in reference to
    public let pronouns: [String]?
    public let aboutText: String?
}
