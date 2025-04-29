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
	public let anchorType: AnchorTypes
	public let anchorTo: AnchorTo
}

extension AnchorAttestation: LinearEncodedPair {
	public var first: UInt16 { anchorTo.type.rawValue }
	public var second: Data { anchorTo.stableEncoded }

	public init(
		first: UInt16,
		second: Data,
	) throws {
		let (type, anchorTo) = try Self.anchorToFactory(type: first, encoded: second)

		self.init(
			anchorType: type,
			anchorTo: anchorTo,
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
