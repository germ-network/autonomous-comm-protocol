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
		//previously, 1.0.0
		static let currentVersion = SemanticVersion(major: 2, minor: 0, patch: 0)
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

public enum ImageType: UInt8, Sendable {
	case jpegXL = 1
}

public struct DescribedImage: Equatable, Sendable {
	public let imageType: ImageType
	public let imageDigest: TypedDigest
	public let altText: String?

	init(imageType: ImageType, imageDigest: TypedDigest, altText: String?) {
		self.imageType = imageType
		self.imageDigest = imageDigest
		self.altText = altText
	}

	public init(
		imageType: ImageType = .jpegXL,
		imageData: Data,
		altText: String?
	) {
		self.imageType = imageType
		self.imageDigest = .init(prefix: .sha256, over: imageData)
		self.altText = altText
	}
}

extension DescribedImage: LinearEncodedTriple {
	public var first: UInt8 { imageType.rawValue }
	public var second: TypedDigest { imageDigest }
	public var third: OptionalString? { .init(altText) }

	public init(first: UInt8, second: TypedDigest, third: OptionalString?) throws {
		guard let type = ImageType(rawValue: first) else {
			throw LinearEncodingError.unexpectedData
		}
		self.init(
			imageType: type,
			imageDigest: second,
			altText: third?.string
		)
	}
}

extension UInt8: LinearEncodable {
	public static func parse(_ input: Data) throws -> (UInt8, Int) {
		guard let first = input.first else {
			throw LinearEncodingError.unexpectedEOF
		}
		return (first, 1)
	}

	public var wireFormat: Data {
		.init([self])
	}
}

extension String {
	public var utf8Data: Data {
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

	public init(
		counter: UInt16, pronouns: [String], aboutText: String?, imageResource: Resource?
	) {
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
