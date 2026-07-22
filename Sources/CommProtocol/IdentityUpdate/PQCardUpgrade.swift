//
//  PQCardUpgrade.swift
//  CommProtocol
//
//  The in-band carrier for upgrading an existing classical card relationship to
//  a post-quantum (TwoMLSPQ) session, negotiated over the relationship's own
//  established session — see the app's `pq-card-in-session-negotiation.md`.
//
//  It rides the same `CommProposal` slot as `.sameAgent` and is signed by the
//  same established agent key over the same `updateMessage + context` binding, so
//  the offer/welcome is bound to the specific MLS proposal that carries it (no
//  out-of-band substitution). The `agentUpdate` is carried inline because the
//  `.sameAgent` frame it displaces still has to deliver that round's version and
//  addresses.
//
//  BACKWARD COMPATIBILITY: this is a NEW `ProposalType` tag. A pre-1.9.0 peer's
//  `LinearEnum` parse of the unknown tag throws and drops the whole message, so
//  this case must ONLY ever be emitted to a peer already confirmed PQ-capable
//  (`AgentUpdate.isPQCapable`, observed inbound). The capability gate lives in the
//  app; this type is the wire carrier.
//

import Foundation

public struct PQCardUpgrade: Sendable, Equatable, Hashable {
	///The displaced `.sameAgent` round's agent update — still delivers this
	///frame's version and addresses.
	public let agentUpdate: AgentUpdate
	public let payload: Payload

	public init(agentUpdate: AgentUpdate, payload: Payload) {
		self.agentUpdate = agentUpdate
		self.payload = payload
	}

	public enum Payload: Sendable, Equatable, Hashable {
		///The offerer's (A)PQ keyPackage — the bytes a capable peer needs to
		///establish the fresh PQ card session.
		case keyPackage(Data)
		///The replier's sealed PQ establishment welcome envelope.
		case welcome(Data)
		///Terminal "I can't establish PQ right now" with a reason code. The
		///offerer stops re-offering until it observes fresh capability.
		case decline(UInt8)

		enum PayloadType: UInt8, LinearEnum {
			case keyPackage = 1
			case welcome
			case decline
		}
	}

	///Mirrors ``AgentUpdate/formatForSigning(updateMessage:context:)`` — the
	///signature binds the upgrade to the MLS proposal (`updateMessage`) and the
	///session `context`.
	func formatForSigning(
		updateMessage: Data,
		context: TypedDigest
	) throws -> Data {
		try wireFormat + updateMessage + context.wireFormat
	}
}

extension PQCardUpgrade: LinearEncodedPair {
	public var first: AgentUpdate { agentUpdate }
	public var second: Payload { payload }

	public init(first: AgentUpdate, second: Payload) throws {
		self.init(agentUpdate: first, payload: second)
	}
}

extension PQCardUpgrade.Payload: LinearEncodable {
	public static func parse(_ input: Data) throws -> (Self, Int) {
		let (type, remainder) = try PayloadType.continuingParse(input)
		switch type {
		case .keyPackage:
			let (body, consumed) = try Data.parse(remainder)
			return (.keyPackage(body), consumed + 1)
		case .welcome:
			let (body, consumed) = try Data.parse(remainder)
			return (.welcome(body), consumed + 1)
		case .decline:
			guard let reason = remainder.first else {
				throw LinearEncodingError.unexpectedEOF
			}
			return (.decline(reason), 2)
		}
	}

	public var wireFormat: Data {
		get throws {
			switch self {
			case .keyPackage(let body):
				try [PayloadType.keyPackage.rawValue] + body.wireFormat
			case .welcome(let body):
				try [PayloadType.welcome.rawValue] + body.wireFormat
			case .decline(let reason):
				Data([PayloadType.decline.rawValue, reason])
			}
		}
	}
}
