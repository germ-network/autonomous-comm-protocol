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
	case jpeg = 2

	///Classify image bytes by magic number, independent of the declared wire label.
	///Senders without a JPEG XL encoder (the App Clip) label their JPEG images
	///`.jpegXL` for backward compatibility, so consumers should trust the bytes,
	///not the label.
	public static func detect(from data: Data) -> ImageType? {
		//JXL raw codestream: FF 0A
		if data.starts(with: [0xFF, 0x0A]) {
			return .jpegXL
		}
		//JXL ISOBMFF container: 00 00 00 0C 4A 58 4C 20 0D 0A 87 0A
		if data.starts(with: [0, 0, 0, 0x0C, 0x4A, 0x58, 0x4C, 0x20, 0x0D, 0x0A, 0x87, 0x0A]) {
			return .jpegXL
		}
		//JPEG: FF D8 FF
		if data.starts(with: [0xFF, 0xD8, 0xFF]) {
			return .jpeg
		}
		return nil
	}
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

extension IdentityMutableData {
	//Precedence is defined by `counter`. The signature only proves the signer
	//authored this update, not that it is newer than one already applied, so a
	//replayed or rolled-back update verifies fine. Callers hold the prior state
	//and MUST gate application on this check to reject stale mutable data.

	///Whether this update should replace `previous` (strictly newer counter).
	public func supersedes(_ previous: IdentityMutableData) -> Bool {
		counter > previous.counter
	}

	///Throwing form of ``supersedes(_:)``. A `nil` predecessor (no prior state)
	///is always accepted; an equal or lower counter throws `.staleUpdate`.
	public func validateSupersedes(_ previous: IdentityMutableData?) throws {
		guard let previous else { return }
		guard supersedes(previous) else {
			throw ProtocolError.staleUpdate
		}
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
