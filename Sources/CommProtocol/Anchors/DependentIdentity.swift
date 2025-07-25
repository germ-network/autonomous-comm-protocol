//
//  Anchors.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 3/6/25.
//

import CryptoKit
import Foundation

public protocol AnchorTo: Sendable {
	static var anchorType: AnchorTypes { get }
	init(type: AnchorTypes, encoded: Data) throws
	var stableEncoded: Data { get }
}

extension AnchorTo {
	public var type: AnchorTypes { Swift.type(of: self).anchorType }
}

public enum AnchorTypes: UInt16, Sendable {
	case atProto = 0
}

//The body, analogous to CoreIdentity
//for simplicity of decoding, pulling out the
//anchor key
public struct DependentIdentity: Sendable {
	public let anchorType: AnchorTypes
	public let anchorTo: AnchorTo

	public init(anchorTo: AnchorTo) {
		self.anchorType = anchorTo.type
		self.anchorTo = anchorTo
	}
}

extension DependentIdentity: Equatable {
	public static func == (lhs: DependentIdentity, rhs: DependentIdentity) -> Bool {
		lhs.archive == rhs.archive
	}
}

extension DependentIdentity: Hashable {
	public func hash(into hasher: inout Hasher) {
		hasher.combine(archive)
	}
}

extension DependentIdentity {
	public struct Archive: Codable, Hashable, Sendable {
		public let anchorType: UInt16
		public let anchorTo: Data

		public init(anchorType: UInt16, anchorTo: Data) {
			self.anchorType = anchorType
			self.anchorTo = anchorTo
		}
	}

	public var archive: Archive {
		.init(anchorType: anchorType.rawValue, anchorTo: anchorTo.stableEncoded)
	}

	public init(archive: Archive) throws {
		(anchorType, anchorTo) = try DependentIdentity.anchorToFactory(
			type: archive.anchorType,
			encoded: archive.anchorTo
		)
	}
}

extension DependentIdentity: LinearEncodedPair {
	public var first: UInt16 { anchorTo.type.rawValue }
	public var second: Data { anchorTo.stableEncoded }

	public init(
		first: UInt16,
		second: Data,
	) throws {
		(anchorType, anchorTo) =
			try Self
			.anchorToFactory(type: first, encoded: second)
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

extension DependentIdentity.Archive: LinearEncodedPair {
	public var first: UInt16 { anchorType }
	public var second: Data { anchorTo }

	public init(first: UInt16, second: Data) throws {
		self.init(anchorType: first, anchorTo: second)
	}
}
