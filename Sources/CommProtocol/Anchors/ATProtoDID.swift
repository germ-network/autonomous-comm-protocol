//
//  ATProtoDID.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 4/22/25.
//

import Foundation

//https://atproto.com/specs/did
//2KB limit, case sensitive,
//https://www.w3.org/TR/did-1.0/#did-syntax

//Store it as a string, do some rudimentary checking
//can implement more checks later

public struct ATProtoDID: Equatable {
	enum Constants {
		static let prefix = "did:"
	}

	public let identifier: String
	public let method: Methods

	public var fullId: String {
		Constants.prefix + method.rawValue + ":" + identifier
	}

	public enum Methods: String, CaseIterable, Sendable {
		case plc
		case web

		static func parse(
			_ subsequence: String.SubSequence
		) throws -> (Self, String) {
			for method in Methods.allCases {
				if subsequence.hasPrefix(method.rawValue + ":") {
					return (
						method,
						String(
							subsequence.dropFirst(
								method.rawValue.count + 1)
						)
					)
				}
			}
			throw ATProtoDIDError.invalidMethod
		}
	}

	public init(method: Methods, identifier: String) {
		self.method = method
		self.identifier = identifier
	}

	public init(fullId: String) throws {
		guard fullId.hasPrefix(Constants.prefix) else {
			throw ATProtoDIDError.invalidPrefix
		}
		let remainder = fullId.dropFirst(Constants.prefix.count)
		(method, identifier) = try Methods.parse(remainder)
	}
}

extension ATProtoDID {
	static public func mock(method: Methods = .plc) -> Self {
		.init(method: method, identifier: UUID().uuidString)
	}
}

enum ATProtoDIDError: Error {
	case invalidPrefix
	case invalidMethod
}

extension ATProtoDIDError: LocalizedError {
	public var errorDescription: String? {
		switch self {
		case .invalidPrefix: "Invalid prefix"
		case .invalidMethod: "Invalid method"
		}
	}
}

extension ATProtoDID: AnchorTo {
	public static let anchorType: AnchorTypes = .atProto

	public init(type: AnchorTypes, encoded: Data) throws {
		guard type == .atProto else {
			throw ProtocolError.incorrectAnchorType
		}
		guard let string = String(data: encoded, encoding: .utf8) else {
			throw ProtocolError.archiveIncorrect
		}
		try self.init(fullId: string)
	}

	public var stableEncoded: Data {
		fullId.utf8Data
	}
}
