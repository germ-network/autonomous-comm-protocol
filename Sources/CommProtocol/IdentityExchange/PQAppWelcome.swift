//
//  PQAppWelcome.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 7/17/26.
//

import Foundation

///The PQ (TwoMLSPQ) card establishment reply: a separate, parallel structure to
///`AppWelcome`, which stays live unchanged on the classical path. No version
///field — routing discriminates (this reply only ever answers a PQ card offer,
///so the recipient knows which struct to parse from the route).
///
///Like `AppWelcome`, this is the application-level data accompanying an MLS
///welcome issued in response to a key package; the difference is the signed
///content carries `PQEstablishmentKeyMaterial` (the CLASSICAL return key
///package plus the commitment to the A.4 bootstrap PQ key package) instead of
///a bare key-package blob. The layouts also diverge at the fifth content
///element, where the key material leads with a checked reserved byte
///(`PQEstablishmentKeyMaterial.discriminator`, `0x00`) sitting where a
///classical welcome carries its key-package `Data` length prefix — a byte a
///classical length prefix can never be — so the signed wire bytes of one
///route die at parse on the other, deterministically in both directions (see
///the discriminator's doc).
public struct PQAppWelcome: Equatable, Sendable {
	public let introduction: IdentityIntroduction
	public let signedContent: SignedObject<Content>

	public struct Content: Equatable, Sendable {
		//No `groupId`: unlike classical `AppWelcome`, a PQ card session's identity is
		//the crate's LOCAL send-group id (each endpoint keys its own), not a shared,
		//initiator-chosen id carried on the wire. The session↔welcome↔identity weld is
		//the born-dedicated establishment handoff over `sha256(welcome)`, so no shared
		//session-id field is needed here (2026-07-21).
		public let agentData: AgentUpdate
		public let seqNo: UInt32  //sets the initial seqNo
		//just as messages assert local send time; kept for template parity
		//with AppWelcome (ruling 2026-07-17) — an unauthenticated sender
		//assertion no consumer reads today
		public let sentTime: WireDate
		public let keyMaterial: PQEstablishmentKeyMaterial
	}

	//This gets transmitted, encrypted to the HPKE init key
	public struct Combined: Equatable, Sendable {
		public let appWelcome: PQAppWelcome
		public let mlsWelcomeData: Data

		public init(appWelcome: PQAppWelcome, mlsMessageData: Data) {
			self.appWelcome = appWelcome
			self.mlsWelcomeData = mlsMessageData
		}
	}
}

extension PQAppWelcome: LinearEncodedPair {
	public var first: IdentityIntroduction { introduction }
	public var second: SignedObject<Content> { signedContent }

	public init(
		first: IdentityIntroduction,
		second: SignedObject<Content>
	) throws {
		self.init(introduction: first, signedContent: second)
	}
}

extension PQAppWelcome.Content: LinearEncodedQuad {
	public var first: AgentUpdate { agentData }
	public var second: UInt32 { seqNo }
	public var third: WireDate { sentTime }
	public var fourth: PQEstablishmentKeyMaterial { keyMaterial }

	public init(
		first: AgentUpdate,
		second: UInt32,
		third: WireDate,
		fourth: PQEstablishmentKeyMaterial
	) throws {
		self.init(
			agentData: first,
			seqNo: second,
			sentTime: third,
			keyMaterial: fourth
		)
	}
}

extension PQAppWelcome.Combined: LinearEncodedPair {
	public var first: PQAppWelcome { appWelcome }
	public var second: Data { mlsWelcomeData }

	public init(first: PQAppWelcome, second: Data) throws {
		self.init(appWelcome: first, mlsMessageData: second)
	}
}

//The PQAppWelcome is encrypted to an assumed published key in HPKE basic mode
//(we don't know the sender ahead of time)
//should presume confidentiality but not authenticity.
//We need to confirm the identity key in the PQAppWelcome signs
//over the remainder of the data in the PQAppWelcome
//some indirectly through the delegate AgentKey
extension PQAppWelcome {
	public struct Validated: Sendable {
		public let coreIdentity: CoreIdentity
		public let introContents: IdentityIntroduction.Contents
		public let imageResource: Resource
		public let welcomeContent: PQAppWelcome.Content
	}

	public func validated(myAgent: AgentPublicKey) throws -> Validated {
		//Seedless PQ establishment context: binds the acceptor's own agent
		//(`myAgent`, the peer the replier answered) and, via `generateContext`,
		//the replier's delegated agent — no session seed (the identity↔welcome
		//weld is the establishment handoff over the welcome digest).
		let agentType = AgentTypes.pqCardEstablishment(remoteAgentId: myAgent)

		guard
			let context = try agentType.generateContext(
				myAgentId: introduction.signedContents.content.agentKey
			)
		else {
			throw ProtocolError.unexpected("mismatched context")
		}

		let (coreIdentity, introContents, imageResource) =
			try introduction
			.validated(context: context)

		return .init(
			coreIdentity: coreIdentity,
			introContents: introContents,
			imageResource: imageResource,
			welcomeContent: try introContents.agentKey
				.validate(signedObject: signedContent)
		)
	}
}

extension AgentPrivateKey {
	public func createPQAppWelcome(
		introduction: IdentityIntroduction,
		agentData: AgentUpdate,
		keyMaterial: PQEstablishmentKeyMaterial
	) throws -> PQAppWelcome {
		let content = PQAppWelcome.Content(
			agentData: agentData,
			seqNo: .random(in: .min...(.max)),
			sentTime: .now,
			keyMaterial: keyMaterial
		)

		let signedContent = try sign(content: content)

		return .init(
			introduction: introduction,
			signedContent: signedContent
		)
	}
}
