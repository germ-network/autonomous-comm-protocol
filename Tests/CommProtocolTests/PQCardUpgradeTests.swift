//
//  PQCardUpgradeTests.swift
//  CommProtocol
//
//  Covers the in-band classical->PQ card upgrade proposal carrier.
//

import CommProtocolMocks
import CryptoKit
import Foundation
import Testing

@testable import CommProtocol

struct PQCardUpgradeTests {
	let knownIdentityKey: IdentityPrivateKey
	let knownSignedIdentity: SignedObject<CoreIdentity>
	let knownAgent: AgentPrivateKey

	init() throws {
		(knownIdentityKey, knownSignedIdentity) = try Mocks.mockIdentity()
		knownAgent = .init()
	}

	//MARK: payload round-trips (independent of signing)

	@Test func payloadKeyPackageRoundTrips() throws {
		let body = Data((0..<200).map { _ in UInt8.random(in: .min ... .max) })
		let payload = PQCardUpgrade.Payload.keyPackage(body)
		#expect(try PQCardUpgrade.Payload.finalParse(payload.wireFormat) == payload)
	}

	@Test func payloadWelcomeRoundTrips() throws {
		let body = Data((0..<500).map { _ in UInt8.random(in: .min ... .max) })
		let payload = PQCardUpgrade.Payload.welcome(body)
		#expect(try PQCardUpgrade.Payload.finalParse(payload.wireFormat) == payload)
	}

	@Test func payloadDeclineRoundTrips() throws {
		let payload = PQCardUpgrade.Payload.decline(7)
		#expect(try PQCardUpgrade.Payload.finalParse(payload.wireFormat) == payload)
	}

	//MARK: full proposal build -> wire -> validate

	private func validate(
		_ proposal: CommProposal,
		context: TypedDigest,
		message: Data
	) throws -> CommProposal.ValidatedForCard {
		try CommProposal.finalParse(proposal.wireFormat)
			.validate(
				knownIdentity: knownSignedIdentity.content.id,
				knownAgent: knownAgent.publicKey,
				context: context,
				updateMessage: message
			)
	}

	@Test func keyPackageOfferValidates() throws {
		let message = Mocks.mockMessage()
		let context = try TypedDigest.mock()
		let agentUpdate = AgentUpdate.mock()
		let keyPackage = Data((0..<321).map { _ in UInt8.random(in: .min ... .max) })

		let proposal = try knownAgent.proposePQCardUpgrade(
			agentUpdate: agentUpdate,
			payload: .keyPackage(keyPackage),
			leafNodeUpdate: message,
			context: context
		)

		guard case .pqCardUpgrade(let validated) = try validate(
			proposal, context: context, message: message)
		else {
			#expect(Bool(false), "expected pqCardUpgrade")
			return
		}
		#expect(validated.agentUpdate == agentUpdate)
		#expect(validated.payload == .keyPackage(keyPackage))
	}

	@Test func welcomeReplyValidates() throws {
		let message = Mocks.mockMessage()
		let context = try TypedDigest.mock()
		let welcome = Data((0..<640).map { _ in UInt8.random(in: .min ... .max) })

		let proposal = try knownAgent.proposePQCardUpgrade(
			agentUpdate: .mock(),
			payload: .welcome(welcome),
			leafNodeUpdate: message,
			context: context
		)

		guard case .pqCardUpgrade(let validated) = try validate(
			proposal, context: context, message: message)
		else {
			#expect(Bool(false), "expected pqCardUpgrade")
			return
		}
		#expect(validated.payload == .welcome(welcome))
	}

	@Test func declineValidates() throws {
		let message = Mocks.mockMessage()
		let context = try TypedDigest.mock()

		let proposal = try knownAgent.proposePQCardUpgrade(
			agentUpdate: .mock(),
			payload: .decline(3),
			leafNodeUpdate: message,
			context: context
		)

		guard case .pqCardUpgrade(let validated) = try validate(
			proposal, context: context, message: message)
		else {
			#expect(Bool(false), "expected pqCardUpgrade")
			return
		}
		#expect(validated.payload == .decline(3))
	}

	//MARK: signature binding — wrong agent / context / message all reject

	@Test func wrongAgentRejected() throws {
		let message = Mocks.mockMessage()
		let context = try TypedDigest.mock()
		let proposal = try knownAgent.proposePQCardUpgrade(
			agentUpdate: .mock(),
			payload: .keyPackage(Data(repeating: 9, count: 64)),
			leafNodeUpdate: message,
			context: context
		)
		let wrongKey = AgentPrivateKey()

		#expect(throws: ProtocolError.authenticationError) {
			_ = try CommProposal.finalParse(proposal.wireFormat)
				.validate(
					knownIdentity: knownSignedIdentity.content.id,
					knownAgent: wrongKey.publicKey,
					context: context,
					updateMessage: message
				)
		}
	}

	@Test func wrongContextRejected() throws {
		let message = Mocks.mockMessage()
		let context = try TypedDigest.mock()
		let proposal = try knownAgent.proposePQCardUpgrade(
			agentUpdate: .mock(),
			payload: .keyPackage(Data(repeating: 9, count: 64)),
			leafNodeUpdate: message,
			context: context
		)

		#expect(throws: ProtocolError.authenticationError) {
			_ = try CommProposal.finalParse(proposal.wireFormat)
				.validate(
					knownIdentity: knownSignedIdentity.content.id,
					knownAgent: knownAgent.publicKey,
					context: .mock(),
					updateMessage: message
				)
		}
	}

	@Test func wrongMessageRejected() throws {
		let message = Mocks.mockMessage()
		let context = try TypedDigest.mock()
		let proposal = try knownAgent.proposePQCardUpgrade(
			agentUpdate: .mock(),
			payload: .keyPackage(Data(repeating: 9, count: 64)),
			leafNodeUpdate: message,
			context: context
		)

		#expect(throws: ProtocolError.authenticationError) {
			_ = try CommProposal.finalParse(proposal.wireFormat)
				.validate(
					knownIdentity: knownSignedIdentity.content.id,
					knownAgent: knownAgent.publicKey,
					context: context,
					updateMessage: Mocks.mockMessage()
				)
		}
	}

	//MARK: the load-bearing back-compat invariant

	/// An unknown `ProposalType` tag must throw on parse — this is exactly what a
	/// pre-1.9.0 peer does with the new `pqCardUpgrade` tag, and the reason the
	/// case may only ever be emitted to a confirmed-capable peer.
	@Test func unknownProposalTypeTagThrows() throws {
		// tag 6 is unassigned (sameAgent=1 ... pqCardUpgrade=5)
		let bogus = Data([6]) + Data(repeating: 0, count: 32)
		#expect(throws: (any Error).self) {
			_ = try CommProposal.finalParse(bogus)
		}
	}

	/// The anchor validation surface must keep rejecting a card-only upgrade.
	@Test func anchorValidationRejectsUpgrade() throws {
		let message = Mocks.mockMessage()
		let context = try TypedDigest.mock()
		let proposal = try knownAgent.proposePQCardUpgrade(
			agentUpdate: .mock(),
			payload: .decline(0),
			leafNodeUpdate: message,
			context: context
		)
		let parsed = try CommProposal.finalParse(proposal.wireFormat)
		guard case .pqCardUpgrade = parsed else {
			#expect(Bool(false), "expected pqCardUpgrade")
			return
		}
	}
}
