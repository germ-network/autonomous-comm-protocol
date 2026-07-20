//
//  PQEstablishmentHandoffTests.swift
//  CommProtocol
//
//  Pins the born-dedicated establishment delegation (TwoMLSPQ contract 26):
//  the identity-signed handoff artifact that rides the establishment staple
//  next to the spec-conformant return welcome, with every TBS slot derived
//  from the welcome bytes (`PQEstablishmentBinding`) so the delegation cannot
//  be detached from the exact group being joined, nor cross-validate as a
//  steady-state rotation handoff.
//

import AtprotoTypes
import AtprotoTypesMocks
import CommProtocolMocks
import CryptoKit
import Foundation
import Testing

@testable import CommProtocol

//MARK: - Card arm

struct PQCardEstablishmentHandoffTests {
	let identityKey: IdentityPrivateKey
	let signedIdentity: SignedObject<CoreIdentity>
	//the acceptor's published card agent — the peer the initiator already knows
	let invitationAgent = AgentPrivateKey()
	//the fresh per-session principal the session was born under
	let dedicatedAgent = AgentPrivateKey()
	//stands in for the return welcome the session layer produced
	let welcome = SymmetricKey(size: .bits256).rawRepresentation

	init() throws {
		(identityKey, signedIdentity) = try Mocks.mockIdentity()
	}

	private func mint(
		welcome: Data,
		agentData: AgentUpdate = .mock()
	) throws -> PQCardEstablishmentHandoff {
		let input = AgentHandoff.Input(
			existingIdentity: signedIdentity.content.id,
			identityDelegate: try identityKey.createAgentDelegate(
				for: dedicatedAgent.publicKey,
				context: PQEstablishmentBinding.context(welcome: welcome)
			),
			signedIdentityMutable: nil,
			establishedAgent: invitationAgent.publicKey
		)
		return try dedicatedAgent.completePQCardEstablishment(
			input: input,
			agentData: agentData,
			welcome: welcome
		)
	}

	@Test func roundTripValidates() throws {
		let agentData = AgentUpdate.mock()
		let handoff = try mint(welcome: welcome, agentData: agentData)

		//wire round-trip before verification, as the initiator sees it
		let received = try PQCardEstablishmentHandoff.finalParse(
			try handoff.wireFormat)

		let validated = try received.validated(
			knownIdentity: signedIdentity.content.id,
			knownAgent: invitationAgent.publicKey,
			welcome: welcome
		)
		//the delegation names exactly the dedicated agent; the session layer
		//separately requires this key to equal the welcome's creator leaf
		#expect(validated.newAgent == dedicatedAgent.publicKey)
		#expect(validated.agentData == agentData)
	}

	@Test func rejectsTamperedWelcome() throws {
		let handoff = try mint(welcome: welcome)
		//the signatures bind H(welcome): any other welcome must fail, so the
		//delegation cannot be spliced onto a different establishment
		var tampered = welcome
		tampered[tampered.startIndex] ^= 0x01
		#expect(throws: (any Error).self) {
			_ = try handoff.validated(
				knownIdentity: signedIdentity.content.id,
				knownAgent: invitationAgent.publicKey,
				welcome: tampered
			)
		}
	}

	@Test func rejectsWrongIdentity() throws {
		let handoff = try mint(welcome: welcome)
		let (_, otherIdentity) = try Mocks.mockIdentity()
		#expect(throws: (any Error).self) {
			_ = try handoff.validated(
				knownIdentity: otherIdentity.content.id,
				knownAgent: invitationAgent.publicKey,
				welcome: welcome
			)
		}
	}

	@Test func rejectsWrongInvitationAgent() throws {
		//the invitation agent does not sign, but it is NAMED in the signed
		//body — validating against any other known agent must fail
		let handoff = try mint(welcome: welcome)
		#expect(throws: (any Error).self) {
			_ = try handoff.validated(
				knownIdentity: signedIdentity.content.id,
				knownAgent: AgentPrivateKey().publicKey,
				welcome: welcome
			)
		}
	}

	@Test func establishmentCannotCrossValidateAsRotation() throws {
		//a steady-state rotation fills updateMessage with a bare TypedDigest
		//wire form (the MLS Update digest) and context with the session's
		//proposal context; the establishment artifact must fail under those
		//fills — the delegation is not a rotation proposal
		let handoff = try mint(welcome: welcome)
		let rotationContext = try TypedDigest.mock()
		#expect(throws: (any Error).self) {
			_ = try handoff.agentHandoff.validate(
				knownAgent: invitationAgent.publicKey,
				newAgent: dedicatedAgent.publicKey,
				newAgentIdentity: signedIdentity.content.id,
				context: rotationContext,
				updateMessage: rotationContext.wireFormat
			)
		}
		#expect(throws: (any Error).self) {
			_ = try handoff.identityDelegate.validate(
				knownIdentity: signedIdentity.content.id,
				context: rotationContext
			)
		}
		//the length-separation pin: even with the CORRECT establishment
		//context, a rotation-style 33-byte updateMessage must fail — the
		//establishment PoP signed an EMPTY slot, so the TBS lengths differ
		//before any value comparison
		#expect(throws: (any Error).self) {
			_ = try handoff.agentHandoff.validate(
				knownAgent: invitationAgent.publicKey,
				newAgent: dedicatedAgent.publicKey,
				newAgentIdentity: signedIdentity.content.id,
				context: PQEstablishmentBinding.context(welcome: welcome),
				updateMessage: try TypedDigest.mock().wireFormat
			)
		}
	}

	@Test func rejectsEmptyWelcomeAtCreate() throws {
		#expect(throws: (any Error).self) {
			_ = try mint(welcome: Data())
		}
	}

	@Test func wireContractPinsLeadingByte() throws {
		let handoff = try mint(welcome: welcome)
		let wire = try handoff.wireFormat
		#expect(wire.first == PQCardEstablishmentHandoff.discriminator)
		#expect(PQCardEstablishmentHandoff.discriminator == 0x01)
	}

	@Test func cardBytesRejectAsAnchor() throws {
		//cross-arm parse dies deterministically at the leading byte, before
		//any signature machinery runs
		let wire = try mint(welcome: welcome).wireFormat
		#expect(throws: (any Error).self) {
			_ = try PQAnchorEstablishmentHandoff.finalParse(wire)
		}
	}
}

//MARK: - Anchor arm

struct PQAnchorEstablishmentHandoffTests {
	let acceptorDID = Atproto.DID.mock()
	let acceptorAnchor: PrivateActiveAnchor
	//the acceptor's published hello agent — the invitation agent the
	//initiator already knows, and the RETIRED signer of the handoff
	let invitationAgent: PrivateAnchorAgent
	let dedicatedAgent = AgentPrivateKey()
	let welcome = SymmetricKey(size: .bits256).rawRepresentation

	init() throws {
		acceptorAnchor = .create(for: acceptorDID)
		invitationAgent = acceptorAnchor.createHelloAgent()
	}

	private var knownAnchor: PublicAnchorAgent {
		.init(
			anchor: acceptorAnchor.publicAnchor,
			agentKey: invitationAgent.publicKey
		)
	}

	private func mint(
		welcome: Data,
		agentUpdate: AgentUpdate = .mock()
	) throws -> PQAnchorEstablishmentHandoff {
		try acceptorAnchor.createPQAnchorEstablishmentHandoff(
			agentUpdate: agentUpdate,
			newAgent: dedicatedAgent,
			from: invitationAgent,
			welcome: welcome
		)
	}

	@Test func roundTripVerifies() throws {
		let agentUpdate = AgentUpdate.mock()
		let handoff = try mint(welcome: welcome, agentUpdate: agentUpdate)

		let received = try PQAnchorEstablishmentHandoff.finalParse(
			try handoff.wireFormat)

		let verified = try received.validated(
			knownAnchor: knownAnchor,
			welcome: welcome
		)
		#expect(verified.agent.agentKey == dedicatedAgent.publicKey)
		#expect(verified.newAgentUpdate == agentUpdate)
		//same-anchor establishment: no anchor succession rides the handoff
		#expect(verified.newAnchor == false)
	}

	@Test func rejectsTamperedWelcome() throws {
		let handoff = try mint(welcome: welcome)
		var tampered = welcome
		tampered[tampered.startIndex] ^= 0x01
		#expect(throws: (any Error).self) {
			_ = try handoff.validated(knownAnchor: knownAnchor, welcome: tampered)
		}
	}

	@Test func rejectsWrongInvitationAgent() throws {
		//all three signatures bind the known (retired/invitation) agent; a
		//different one must fail even with the right anchor
		let handoff = try mint(welcome: welcome)
		let otherAgent = acceptorAnchor.createHelloAgent()
		#expect(throws: (any Error).self) {
			_ = try handoff.validated(
				knownAnchor: .init(
					anchor: acceptorAnchor.publicAnchor,
					agentKey: otherAgent.publicKey
				),
				welcome: welcome
			)
		}
	}

	@Test func rejectsWrongAnchor() throws {
		let handoff = try mint(welcome: welcome)
		let otherAnchor = PrivateActiveAnchor.create(for: Atproto.DID.mock())
		#expect(throws: (any Error).self) {
			_ = try handoff.validated(
				knownAnchor: .init(
					anchor: otherAnchor.publicAnchor,
					agentKey: invitationAgent.publicKey
				),
				welcome: welcome
			)
		}
	}

	@Test func establishmentCannotCrossValidateAsRotation() throws {
		//a steady-state anchor rotation verifies with (groupContext = the
		//session's group-id digest, mlsUpdateDigest = the MLS Update digest);
		//the establishment artifact must fail under those fills
		let handoff = try mint(welcome: welcome)
		#expect(throws: (any Error).self) {
			_ = try knownAnchor.verify(
				anchorHandoff: handoff.anchorHandoff,
				context: try TypedDigest.mock(),
				mlsUpdateDigest: try TypedDigest.mock()
			)
		}
	}

	@Test func rejectsEmptyWelcomeAtCreate() throws {
		#expect(throws: (any Error).self) {
			_ = try mint(welcome: Data())
		}
	}

	@Test func wireContractPinsLeadingByte() throws {
		let wire = try mint(welcome: welcome).wireFormat
		#expect(wire.first == PQAnchorEstablishmentHandoff.discriminator)
		#expect(PQAnchorEstablishmentHandoff.discriminator == 0x02)
	}

	@Test func anchorBytesRejectAsCard() throws {
		let wire = try mint(welcome: welcome).wireFormat
		#expect(throws: (any Error).self) {
			_ = try PQCardEstablishmentHandoff.finalParse(wire)
		}
	}
}

//MARK: - Cross-arm binding

struct PQEstablishmentBindingTests {
	@Test func theOneBindingIsDeterministicAndWelcomeSensitive() {
		let welcome = SymmetricKey(size: .bits256).rawRepresentation
		let context = PQEstablishmentBinding.context(welcome: welcome)

		//deterministic: signer and verifier independently derive the same
		//value from the same welcome bytes
		#expect(PQEstablishmentBinding.context(welcome: welcome) == context)
		//welcome-sensitive: any other welcome yields a different binding
		var other = welcome
		other[other.startIndex] ^= 0x01
		#expect(PQEstablishmentBinding.context(welcome: other) != context)
	}
}
