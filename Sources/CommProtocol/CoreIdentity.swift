//
//  File.swift
//
//
//  Created by Mark @ Germ on 6/15/24.
//

import CryptoKit
import Foundation

///CoreIdentity is an identity key that asserts a user-facing representation:
/// - name (assert once)
/// - image (hash, assert once)
/// - pronouns
/// - bindings to other identities
///
public struct CoreIdentity: Codable, Sendable, Equatable {
    struct Constants {
        //previously, 0.0.1
        static let currentVersion = SemanticVersion(major: 1, minor: 0, patch: 0)
    }

    public let id: Data  //WireFormat for IdentityPublicKey
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

    var identityKey: IdentityPublicKey {
        get throws {
            try .init(wireFormat: id)
        }
    }
}

public struct DescribedImage: Equatable, Codable, Sendable {
    //TODO: make this a typed digest
    public let imageDigest: Data
    public let altText: String?

    public init(imageDigest: Data, altText: String?) {
        self.imageDigest = imageDigest
        self.altText = altText
    }
}

extension CoreIdentity: SignableObject {
    public static let type: SignableObjectTypes = .identityRepresentation
}

//MARK: Signed identity
///Bundles the encoded CoreIdentity
///The CoreIdentity contains two variable-length strings, and we expect it to grow, so we leave it JSON-encoded for flexibility
///Because JSON encoding does not produce a stable output, we have to store and exchange the particular encoding that we sign
///
///However, since signedDigest is a predictable width, we can be a bit more efficient by leaving the signedDigest
///in raw bytes and not base64 encoding it
extension SignedObject<CoreIdentity> {
    public func verifiedIdentity() throws -> CoreIdentity {
        //have to decode the credentialData to get the public key
        let coreIdentity: CoreIdentity = try body.decoded()

        //remainder of credential is not valid until we validate the signature
        let identityKey: IdentityPublicKey = try .init(wireFormat: coreIdentity.id)
        let verifiedIdentity = try validate(for: identityKey.publicKey)
        assert(verifiedIdentity == coreIdentity)

        return verifiedIdentity
    }
}

public enum HashAlgorithms: UInt8, DefinedWidthPrefix {
    case sha256  //RFC 6234

    public var contentByteSize: Int { digestWidth }

    private var digestWidth: Int {
        switch self {
        case .sha256: 32
        }
    }
}

public struct IdentityMutableData: SignableObject, Codable, Sendable, Equatable {
    public static let type: SignableObjectTypes = .identityMutableData
    public var type: SignableObjectTypes = .identityMutableData
    public let counter: UInt16  //for predecence defined by the sender/signer
    public let pronouns: [String]?
    public let aboutText: String?
}
