//
//  IdentityFollowup.swift
//
//
//  Created by Mark @ Germ on 6/27/24.
//

import Foundation

//Stapled to every message

//Not worth it yet to optimize out 3 bytes version + 1 byte isAppClip
public struct AgentUpdate: Sendable, Equatable, Hashable {
	public let version: SemanticVersion
	public let isAppClip: Bool
	public let addresses: [ProtocolAddress]

	public init(version: SemanticVersion, isAppClip: Bool, addresses: [ProtocolAddress]) {
		self.version = version
		self.isAppClip = isAppClip
		self.addresses = addresses
	}

	func formatForSigning(
		updateMessage: Data,
		context: TypedDigest
	) throws -> Data {
		try wireFormat + updateMessage + context.wireFormat
	}
}

extension AgentUpdate: LinearEncodedTriple {
	public var first: SemanticVersion { version }
	public var second: Bool { isAppClip }
	public var third: [ProtocolAddress] { addresses }

	public init(
		first: SemanticVersion,
		second: Bool,
		third: [ProtocolAddress]
	) throws {
		self.init(version: first, isAppClip: second, addresses: third)
	}
}
