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
    let nonce: Data

    init(
        id: IdentityPublicKey,
        name: String,
        describedImage: DescribedImage,
        version: SemanticVersion,
        nonce: Data
    ) throws {
        self.id = id
        self.name = name
        self.describedImage = describedImage
        self.version = version
        self.nonce = nonce
    }
}

extension CoreIdentity: LinearEncodedQuintuple {
    var first: TypedKeyMaterial { id.id }
    var second: String { name }
    var third: DescribedImage { describedImage }
    var fourth: SemanticVersion { version }
    var fifth: Data { nonce }

    init(
        first: TypedKeyMaterial,
        second: String,
        third: DescribedImage,
        fourth: SemanticVersion,
        fifth: Data
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

    public init(imageDigest: TypedDigest, altText: String?) {
        self.imageDigest = imageDigest
        self.altText = altText
    }
}

extension DescribedImage: LinearEncodedPair {
    var first: TypedDigest { imageDigest }
    var second: OptionalString? { .init(altText) }

    init(first: TypedDigest, second: OptionalString?) throws {
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
}

public struct IdentityMutableData: Sendable, Equatable {
    public let counter: UInt16  //for predecence defined by the sender/signer
    public let pronouns: [String]
    public let aboutText: String?

    public init(counter: UInt16, pronouns: [String], aboutText: String?) {
        self.counter = counter
        self.pronouns = pronouns
        self.aboutText = aboutText
    }
}

extension IdentityMutableData: LinearEncodedTriple {
    var first: UInt16 { counter }
    var second: [String] { pronouns }
    var third: String? { aboutText }

    init(first: UInt16, second: [String], third: String?) throws {
        self.init(counter: first, pronouns: second, aboutText: third)
    }
}
