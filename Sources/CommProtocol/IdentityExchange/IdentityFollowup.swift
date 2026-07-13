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

extension AgentUpdate {
	///The agent version at (and above) which handoff signing bodies become
	///domain-separated (see `AgentHandoff.NewAgentTBS`).
	///
	///This shadows the post-quantum rollout: PQ capability is advertised by an
	///agent version at or above a threshold (the field legacy peers already
	///parse — see the app's `pq-card-in-session-negotiation.md`), so domain
	///separation rides that same version bump rather than a flag day of its own.
	///Classical (sub-threshold) agents keep the pre-separation body byte-for-byte.
	///
	///Placeholder above the current agent version so it is inert today; the value
	///is the single coordination point and must match the app's PQ-capability
	///threshold when PQ ships.
	public static let pqDomainSeparationVersion = SemanticVersion(
		major: 3,
		minor: 0,
		patch: 0
	)

	///Whether this agent's handoff signing body carries the domain-separation
	///discriminator, per ``pqDomainSeparationVersion``.
	var domainSeparatesHandoff: Bool {
		version >= Self.pqDomainSeparationVersion
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
