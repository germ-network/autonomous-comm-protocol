//
//  PQAnchorWelcome.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 7/17/26.
//

import Foundation

///The PQ (TwoMLSPQ) establishment reply: a separate, parallel structure to
///`AnchorWelcome`, which stays live unchanged on the classical path. No version
///field — routing discriminates (this reply only ever answers a PQ hello, so
///the recipient knows which struct to parse from the route, not the bytes).
///
///Differences from `AnchorWelcome`:
/// - the welcome carries `PQEstablishmentKeyMaterial`: the replier's CLASSICAL
///   return key package plus the commitment to the A.4 bootstrap PQ key package
///   (see that type for the binding rationale)
///
///Signature bodies use fresh discriminators ("PQAnchorReply.*"), so a signature
///over a classical `AnchorWelcome` can never validate as a `PQAnchorWelcome`,
///or vice versa.
///
///Same pattern as AnchorHello/AnchorWelcome:
///- Inner content that we are transmitting
///- Signatures constructed from the content, maybe with additional context
///- Wrap those in one data structure signed with the known key
///- Mix in additional context as needed when verifying the outer signature
public struct PQAnchorWelcome: LinearEncodedPair, Sendable {
	public let first: TypedSignature
	public let second: Data  //Package.wireformat

	public init(first: TypedSignature, second: Data) {
		self.first = first
		self.second = second
	}
}

extension PQAnchorWelcome {
	public struct Welcome: Sendable {
		public let agentUpdate: AgentUpdate
		public let seqNo: UInt32
		//deliberately kept for template parity with AnchorWelcome (ruling
		//2026-07-17): an unauthenticated sender assertion no consumer reads
		//today — do not trust it for anything without adding validation
		public let sentTime: WireDate
		public let keyMaterial: PQEstablishmentKeyMaterial

		public init(
			agentUpdate: AgentUpdate,
			seqNo: UInt32,
			sentTime: WireDate,
			keyMaterial: PQEstablishmentKeyMaterial
		) {
			self.agentUpdate = agentUpdate
			self.seqNo = seqNo
			self.sentTime = sentTime
			self.keyMaterial = keyMaterial
		}
	}

	public struct Content: Sendable {
		public let attestation: DependentIdentity  //sender
		public let agentKeyMaterial: TypedKeyMaterial  //AgentPublicKey
		public let welcome: Welcome
		public let mlsWelcomeData: Data

		public init(
			attestation: DependentIdentity,
			agentKeyMaterial: TypedKeyMaterial,
			welcome: Welcome,
			mlsWelcomeData: Data
		) {
			self.attestation = attestation
			self.agentKeyMaterial = agentKeyMaterial
			self.welcome = welcome
			self.mlsWelcomeData = mlsWelcomeData
		}

		func agentSignatureBody(
			recipient: PublicAnchor
		) -> AgentSignatureBody {
			.init(
				first: PQAnchorWelcome.AgentSignatureBody.discriminator,
				second: self,
				third: recipient
			)
		}
	}

	struct Package: LinearEncodedPair {
		let first: Content  //Content.wireformat
		let second: TypedSignature  //delegated agent signature
	}

	struct AgentSignatureBody: LinearEncodedTriple {
		static let discriminator = "PQAnchorReply.AgentSignatureBody"
		let first: String  //discriminator maps 1:1 to the delegation type
		let second: Content
		//injected context for the recipient
		let third: PublicAnchor
	}

	struct AnchorSignatureBody: LinearEncodedQuad {
		static let discriminator = "PQAnchorReply.AnchorSignatureBody"
		let first: String  //discriminator maps 1:1 to the delegation type
		let second: Data  //Package.wireformat
		let third: TypedKeyMaterial  //sender AnchorPublicKey
		//injected context for the recipient
		let fourth: PublicAnchor

		init(
			first: String,
			second: Data,
			third: TypedKeyMaterial,
			fourth: PublicAnchor,
		) {
			self.first = first
			self.second = second
			self.third = third
			self.fourth = fourth
		}

		init(
			encodedPackage: Data,
			knownAnchor: AnchorPublicKey,
			recipient: PublicAnchor,
		) {
			self.init(
				first: Self.discriminator,
				second: encodedPackage,
				third: knownAnchor.archive,
				fourth: recipient,
			)
		}
	}

	public struct Verified: Sendable {
		public let agent: PublicAnchorAgent
		public let welcome: Welcome
		public let mlsWelcomeData: Data
	}
}

extension PQAnchorWelcome.Welcome: LinearEncodedQuad {
	public var first: AgentUpdate { agentUpdate }
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
			agentUpdate: first,
			seqNo: second,
			sentTime: third,
			keyMaterial: fourth
		)
	}
}

extension PQAnchorWelcome.Content: LinearEncodedQuad {
	public var first: DependentIdentity { attestation }
	public var second: TypedKeyMaterial { agentKeyMaterial }
	public var third: PQAnchorWelcome.Welcome { welcome }
	public var fourth: Data { mlsWelcomeData }

	public init(
		first: DependentIdentity,
		second: TypedKeyMaterial,
		third: PQAnchorWelcome.Welcome,
		fourth: Data
	) throws {
		self.init(
			attestation: first,
			agentKeyMaterial: second,
			welcome: third,
			mlsWelcomeData: fourth
		)
	}
}

extension PrivateActiveAnchor {
	//agent isn't bound to the anchor until this step
	//so we expect the client to generate a fresh agent (no reuse)
	//generate an mlsWelcome, and provide them as input here
	public func createPQAnchorWelcome(
		agentUpdate: AgentUpdate,
		keyMaterial: PQEstablishmentKeyMaterial,
		mlsWelcomeMessage: Data,
		newAgentKey: AgentPrivateKey,
		recipient: PublicAnchor,
		newSeqNo: UInt32
	) throws -> (PrivateAnchorAgent, PQAnchorWelcome, PQAnchorWelcome.Content) {
		let content = PQAnchorWelcome.Content(
			attestation: attestation,
			agentKeyMaterial: newAgentKey.publicKey.id,
			welcome: .init(
				agentUpdate: agentUpdate,
				seqNo: newSeqNo,
				sentTime: .now,
				keyMaterial: keyMaterial
			),
			mlsWelcomeData: mlsWelcomeMessage
		)

		let package = PQAnchorWelcome.Package(
			first: content,
			second:
				try newAgentKey
				.signer(
					content
						.agentSignatureBody(recipient: recipient)
						.wireFormat
				)
		)

		let outerSignature = try privateKey.signer(
			try PQAnchorWelcome.AnchorSignatureBody(
				encodedPackage: try package.wireFormat,
				knownAnchor: publicKey,
				recipient: recipient,
			).wireFormat
		)

		let reply = PQAnchorWelcome(
			first: outerSignature,
			second: try package.wireFormat
		)

		return (
			.init(
				privateKey: newAgentKey,
				source: .reply
			),
			reply,
			content
		)
	}
}

extension AnchorPublicKey {
	public func verify(
		pqReply: PQAnchorWelcome,
		recipient: PublicAnchor
	) throws -> PQAnchorWelcome.Verified {
		let verifiedPackage = try verifyPackage(
			pqReply: pqReply,
			recipient: recipient,
		)
		let newAgentKey = try AgentPublicKey(
			archive: verifiedPackage.first.agentKeyMaterial
		)

		let agentSignatureBody = try verifiedPackage.first
			.agentSignatureBody(recipient: recipient)
			.wireFormat

		guard
			newAgentKey.verifier(
				verifiedPackage.second,
				agentSignatureBody
			)
		else {
			throw ProtocolError.authenticationError
		}
		let content = verifiedPackage.first

		return .init(
			agent: .init(
				anchor: .init(
					publicKey: self,
					attestation: content.attestation
				),
				agentKey: newAgentKey
			),
			welcome: content.welcome,
			mlsWelcomeData: content.mlsWelcomeData
		)
	}

	private func verifyPackage(
		pqReply: PQAnchorWelcome,
		recipient: PublicAnchor,
	) throws -> PQAnchorWelcome.Package {
		guard
			verifier(
				pqReply.first,
				try PQAnchorWelcome.AnchorSignatureBody(
					encodedPackage: pqReply.second,
					knownAnchor: self,
					recipient: recipient,
				).wireFormat
			)
		else {
			throw ProtocolError.authenticationError
		}

		return try .finalParse(pqReply.second)
	}
}
