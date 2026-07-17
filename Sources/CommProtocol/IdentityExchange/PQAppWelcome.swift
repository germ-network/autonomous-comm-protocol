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
///a bare key-package blob. The layouts also diverge structurally at the fifth
///content element (nested pair vs Data), so the signed wire bytes of one never
///parse as the other.
public struct PQAppWelcome: Equatable, Sendable {
	public let introduction: IdentityIntroduction
	public let signedContent: SignedObject<Content>

	public struct Content: Equatable, Sendable {
		public let groupId: DataIdentifier
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

extension PQAppWelcome.Content: LinearEncodedQuintuple {
	public var first: DataIdentifier { groupId }
	public var second: AgentUpdate { agentData }
	public var third: UInt32 { seqNo }
	public var fourth: WireDate { sentTime }
	public var fifth: PQEstablishmentKeyMaterial { keyMaterial }

	public init(
		first: DataIdentifier,
		second: AgentUpdate,
		third: UInt32,
		fourth: WireDate,
		fifth: PQEstablishmentKeyMaterial
	) throws {
		self.init(
			groupId: first,
			agentData: second,
			seqNo: third,
			sentTime: fourth,
			keyMaterial: fifth
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
		let agentType = AgentTypes.welcome(
			remoteAgentId: myAgent,
			groupId: signedContent.content.groupId
		)

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
		groupId: DataIdentifier,
		keyMaterial: PQEstablishmentKeyMaterial
	) throws -> PQAppWelcome {
		let content = PQAppWelcome.Content(
			groupId: groupId,
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
