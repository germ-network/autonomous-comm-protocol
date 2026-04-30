//
//  AtprotoDiD+AnchorTo.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 3/17/26.
//

import AtprotoTypes
import Foundation

extension Atproto.DID: AnchorTo {
	public static let anchorType: AnchorTypes = .atProto

	public init(type: AnchorTypes, encoded: Data) throws {
		guard type == .atProto else {
			throw ProtocolError.incorrectAnchorType
		}
		guard let string = String(data: encoded, encoding: .utf8) else {
			throw ProtocolError.archiveIncorrect
		}
		try self.init(string: string)
	}

	public var stableEncoded: Data {
		rawValue.utf8Data
	}
}

extension AnchorTo {
	public var asDid: Atproto.DID? {
		guard let did = self as? Atproto.DID else {
			return nil
		}
		return did
	}
}
