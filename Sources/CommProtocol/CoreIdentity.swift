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
    let nonce: DeclaredWidthData

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
        self.nonce = try .init(body: nonce)
    }
}

extension CoreIdentity: LinearEncodable {
    public static func parse(_ input: Data) throws -> (CoreIdentity, Int) {
        let (id, name, describedImage, version, nonce, consumed) =
            try LinearEncoder
            .decode(
                TypedKeyMaterial.self,
                String.self,
                DescribedImage.self,
                SemanticVersion.self,
                DeclaredWidthData.self,
                input: input
            )

        let result = try CoreIdentity(
            id: try .init(archive: id),
            name: name,
            describedImage: describedImage,
            version: version,
            nonce: nonce.body
        )
        return (result, consumed)

    }

    public var wireFormat: Data {
        get throws {
            try id.id.wireFormat
                + name.wireFormat
                + describedImage.wireFormat
                + version.wireFormat
                + nonce.wireFormat
        }
    }

}

public struct DescribedImage: Equatable, Sendable {
    //TODO: make this a typed digest
    public let imageDigest: TypedDigest
    public let altText: String?

    public init(imageDigest: TypedDigest, altText: String?) {
        self.imageDigest = imageDigest
        self.altText = altText
    }
}

extension DescribedImage: LinearEncodable {
    public static func parse(_ input: Data) throws -> (DescribedImage, Int) {
        let (digest, altText, consumed) = try LinearEncoder.decode(
            TypedDigest.self,
            OptionalString.self,
            input: input
        )
        let value = DescribedImage(
            imageDigest: digest,
            altText: altText.string
        )
        return (value, consumed)
    }

    public var wireFormat: Data {
        get throws {
            try imageDigest.wireFormat
                + OptionalString(altText).wireFormat
        }
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

extension CoreIdentity: DeprecateSignableObject {
    public static let type: SignableObjectTypes = .identityRepresentation
}

public struct SignedIdentity: Sendable {
    let encodedIdentity: Data  //Linear encoded CoreIdentity, freeze what's signed over
    let signature: TypedSignature

    public func verifiedIdentity() throws -> CoreIdentity {
        //have to decode the credentialData to get the public key
        let coreIdentity: CoreIdentity = try CoreIdentity.finalParse(encodedIdentity)
        try coreIdentity.id.validate(signature: signature, for: encodedIdentity)

        return coreIdentity
    }
}

extension SignedIdentity: LinearEncodable {
    public static func parse(_ input: Data) throws -> (SignedIdentity, Int) {
        let (_, consumed) = try CoreIdentity.parse(input)
        let encodedIdentity = input.prefix(consumed)

        let slice = input.suffix(from: input.startIndex + consumed)
        let (signature, secondConsumed) = try TypedSignature.parse(slice)

        let result = SignedIdentity(
            encodedIdentity: encodedIdentity,
            signature: signature
        )
        return (result, consumed + secondConsumed)
    }

    public var wireFormat: Data {
        encodedIdentity + signature.wireFormat
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

public struct IdentityMutableData: DeprecateSignableObject, Codable, Sendable, Equatable {
    public static let type: SignableObjectTypes = .identityMutableData
    public var type: SignableObjectTypes = .identityMutableData
    public let counter: UInt16  //for predecence defined by the sender/signer
    public let pronouns: [String]?
    public let aboutText: String?
}
