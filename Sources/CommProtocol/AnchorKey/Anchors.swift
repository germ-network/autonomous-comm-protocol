//
//  Anchors.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 3/6/25.
//

import CryptoKit
import Foundation

public struct ATProtoAnchor: Equatable {
	static let discriminator = "anchor"

	public let did: ATProtoDID
	public let previousDigest: Data?

	func formatForSigning(anchorKey: AnchorPublicKey) -> Data {
		Data((Self.discriminator + did.fullId).utf8)
			+ anchorKey.wireFormat
			+ (previousDigest ?? .init())
	}
}

extension ATProtoAnchor: LinearEncodedPair {
	public var first: String { did.fullId }
	public var second: Data? { previousDigest }

	public init(first: String, second: Data?) throws {
		self.init(
			did: try .init(fullId: first),
			previousDigest: second,
		)
	}
}
