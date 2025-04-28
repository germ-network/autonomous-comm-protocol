//
//  Anchors.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 3/6/25.
//

import CryptoKit
import Foundation

public protocol AnchorTo {
	static var anchorType: AnchorTypes { get }
	init(type: AnchorTypes, encoded: Data) throws
	var stableEncoded: Data { get }
}

extension AnchorTo {
	var type: AnchorTypes { Swift.type(of: self).anchorType }
}

public enum AnchorTypes: UInt16, Sendable {
	case atProto = 0
}

//The body, analogous to CoreIdentity
//for simplicity of decoding, pulling out the
//anchor key
public struct AnchorAttestation {
	static let discriminator = "anchor"
	public let anchorType: AnchorTypes
	public let anchorTo: AnchorTo
	public let previousAnchor: AnchorPublicKey?

	struct Format: LinearEncodedQuintuple {
		let first: String
		let second: UInt16
		let third: Data
		let fourth: TypedKeyMaterial
		let fifth: TypedKeyMaterial?
	}

	func formatForSigning(anchorKey: AnchorPublicKey) -> Format {
		.init(
			first: Self.discriminator,
			second: anchorType.rawValue,
			third: anchorTo.stableEncoded,
			fourth: anchorKey.archive,
			fifth: previousAnchor?.archive
		)
	}
}

extension AnchorAttestation: SignableContent {
	public init(wireFormat: Data) throws {
		self = try Self.finalParse(wireFormat)
	}
}

extension AnchorAttestation: LinearEncodedTriple {
	public var first: UInt16 { anchorTo.type.rawValue }
	public var second: Data { anchorTo.stableEncoded }
	public var third: TypedKeyMaterial? { previousAnchor?.archive }

	public init(
		first: UInt16,
		second: Data,
		third: TypedKeyMaterial?,
	) throws {
		let (type, anchorTo) = try Self.anchorToFactory(type: first, encoded: second)

		self.init(
			anchorType: type,
			anchorTo: anchorTo,
			previousAnchor: try third?.asAnchorPublicKey
		)
	}

	static func anchorToFactory(type: UInt16, encoded: Data) throws -> (AnchorTypes, AnchorTo) {
		guard let anchorType = AnchorTypes(rawValue: type) else {
			throw LinearEncodingError.invalidPrefix
		}
		switch anchorType {
		case .atProto:
			return (anchorType, try ATProtoDID(type: .atProto, encoded: encoded))
		}
	}
}

//extension AnchorAttestation: LinearEncodedTriple {
//	public var first: TypedKeyMaterial { publicKey.archive }
//	public var second: Contents { signedContents.content }
//	public var third: TypedSignature { signedContents.signature }
//
//	public init(first: First, second: Second, third: Third) throws {
//		self.init(
//			publicKey: try .init(archive: first),
//			signedContents: .init(content: second, signature: third)
//		)
//	}
//}
