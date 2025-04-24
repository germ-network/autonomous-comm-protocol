//
//  Anchors.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 3/6/25.
//

import CryptoKit
import Foundation

//public struct ATProtoAnchor: Equatable {
//	static let discriminator = "anchor"
//
//	public let did: ATProtoDID
//	public let previousDigest: Data?
//
//	func formatForSigning(anchorKey: AnchorPublicKey) -> Data {
//		Data((Self.discriminator + did.fullId).utf8)
//			+ anchorKey.wireFormat
//			+ (previousDigest ?? .init())
//	}
//}

//extension ATProtoAnchor: LinearEncodedPair {
//	public var first: String { did.fullId }
//	public var second: Data? { previousDigest }
//
//	public init(first: String, second: Data?) throws {
//		self.init(
//			did: try .init(fullId: first),
//			previousDigest: second,
//		)
//	}
//}

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
	let publicKey: AnchorPublicKey
	let signedContents: SignedContent<Contents>

	public struct Contents {
		static let discriminator = "anchor"
		public let anchorTo: AnchorTo
		public let previousAnchor: AnchorPublicKey?

		func formatForSigning(anchorKey: AnchorPublicKey) -> Data {
			Self.discriminator.utf8Data + anchorTo.stableEncoded + anchorKey.wireFormat
				+ (previousAnchor?.wireFormat ?? .init())
		}
	}
}

extension AnchorAttestation.Contents: SignableContent {
	public init(wireFormat: Data) throws {
		self = try Self.finalParse(wireFormat)
	}
}

extension AnchorAttestation.Contents: LinearEncodedTriple {
	public var first: UInt16 { anchorTo.type.rawValue }
	public var second: Data { anchorTo.stableEncoded }
	public var third: TypedKeyMaterial? { previousAnchor?.archive }

	public init(
		first: UInt16,
		second: Data,
		third: TypedKeyMaterial?,
	) throws {
		self.init(
			anchorTo: try Self.anchorToFactory(type: first, encoded: second),
			previousAnchor: try third?.asAnchorPublicKey
		)
	}

	static func anchorToFactory(type: UInt16, encoded: Data) throws -> AnchorTo {
		guard let anchorType = AnchorTypes(rawValue: type) else {
			throw LinearEncodingError.invalidPrefix
		}
		switch anchorType {
		case .atProto:
			return try ATProtoDID(type: .atProto, encoded: encoded)
		}
	}
}
