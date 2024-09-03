//
//  CoreIdentity.swift
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

public struct CoreIdentity: Sendable, Equatable {
    struct Constants {
        //previously, 0.0.1
        static let currentVersion = SemanticVersion(major: 1, minor: 0, patch: 0)
    }

    public let id: IdentityPublicKey  //WireFormat for IdentityPublicKey
    public let name: String
    public let describedImage: DescribedImage
    public let version: SemanticVersion
    public let nonce: DataIdentifier

    init(
        id: IdentityPublicKey,
        name: String,
        describedImage: DescribedImage,
        version: SemanticVersion,
        nonce: DataIdentifier
    ) throws {
        self.id = id
        self.name = name
        self.describedImage = describedImage
        self.version = version
        self.nonce = nonce
    }
}

extension CoreIdentity: LinearEncodedQuintuple {
    public var first: TypedKeyMaterial { id.id }
    public var second: String { name }
    public var third: DescribedImage { describedImage }
    public var fourth: SemanticVersion { version }
    public var fifth: DataIdentifier { nonce }

    public init(
        first: TypedKeyMaterial,
        second: String,
        third: DescribedImage,
        fourth: SemanticVersion,
        fifth: DataIdentifier
    ) throws {
        try self.init(
            id: .init(archive: first),
            name: second,
            describedImage: third,
            version: fourth,
            nonce: fifth
        )
    }
}

public struct DescribedImage: Equatable, Sendable {
    public let imageDigest: TypedDigest
    public let altText: String?

    init(imageDigest: TypedDigest, altText: String?) {
        self.imageDigest = imageDigest
        self.altText = altText
    }

    public init(imageData: Data, altText: String?) {
        self.imageDigest = .init(prefix: .sha256, over: imageData)
        self.altText = altText
    }
}

extension DescribedImage: LinearEncodedPair {
    public var first: TypedDigest { imageDigest }
    public var second: OptionalString? { .init(altText) }

    public init(first: TypedDigest, second: OptionalString?) throws {
        self.init(imageDigest: first, altText: second?.string)
    }
}

extension String {
    var utf8Data: Data {
        Data(utf8)
    }
}

extension Data {
    var utf8String: String? {
        String(bytes: self, encoding: .utf8)
    }
}

extension SignedObject<CoreIdentity> {
    public func verifiedIdentity() throws -> CoreIdentity {
        //have to decode the credentialData to get the public key
        try content.id.validate(signedObject: self)
    }

    //digest of the immutable portion. Can't fold in contents as the
    //imageResource expires and needs to be refreshed
    public var signedIdentityDigest: TypedDigest {
        get throws {
            .init(prefix: .sha256, over: try wireFormat)
        }
    }
}

public struct IdentityMutableData: Sendable, Equatable {
    public let counter: UInt16  //for predecence defined by the sender/signer
    public let pronouns: [String]
    public let aboutText: String?
    public let imageResource: Resource?

    public init(counter: UInt16, pronouns: [String], aboutText: String?, imageResource: Resource?) {
        self.counter = counter
        self.pronouns = pronouns
        self.aboutText = aboutText
        self.imageResource = imageResource
    }
}

extension IdentityMutableData: LinearEncodedQuad {
    public var first: UInt16 { counter }
    public var second: [String] { pronouns }
    public var third: String? { aboutText }
    public var fourth: Resource? { imageResource }

    public init(first: UInt16, second: [String], third: String?, fourth: Resource?) throws {
        self.init(
            counter: first,
            pronouns: second,
            aboutText: third,
            imageResource: fourth
        )
    }
}
