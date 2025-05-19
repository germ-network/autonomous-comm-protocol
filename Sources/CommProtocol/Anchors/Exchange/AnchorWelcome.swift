//
//  AnchorReply.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 4/24/25.
//

import Foundation

//After a user Alex
//- publishes a DID anchor
//- provides some keyPackages (AnchorHello's) to the PDS

//Blair
//- has Alex's anchor key
//- got an AnchorHello

//AnchorReply is constructed for the return, authenticated path
//- expect Alex to know Blair's anchor key

public struct AnchorWelcome: LinearEncodedPair, Sendable {
	public let first: TypedSignature
	public let second: Data  //Package.wireformat

	public init(first: TypedSignature, second: Data) {
		self.first = first
		self.second = second
	}
}

extension AnchorWelcome {
	public struct Welcome: LinearEncodedQuad, Sendable {
		public let first: AgentUpdate
		public let second: UInt32  //seqNo
		public let third: Date
		public let fourth: Data  //keyPackage

		public init(
			first: AgentUpdate,
			second: UInt32,
			third: Date,
			fourth: Data
		) {
			self.first = first
			self.second = second
			self.third = third
			self.fourth = fourth
		}
	}

	public struct Content: LinearEncodedQuad, Sendable {
		public let first: DependentIdentity  //sender
		public let second: TypedKeyMaterial  //AgentPublicKey
		public let third: Welcome
		public let fourth: Data  //MLS Welcome Data

		public init(
			first: DependentIdentity,
			second: TypedKeyMaterial,
			third: Welcome,
			fourth: Data
		) {
			self.first = first
			self.second = second
			self.third = third
			self.fourth = fourth
		}

		func agentSignatureBody(
			recipient: PublicAnchor,
			mlsGroupId: DataIdentifier,
		) -> AgentSignatureBody {
			.init(
				first: AnchorWelcome.AgentSignatureBody.discriminator,
				second: self,
				third: recipient,
				fourth: mlsGroupId
			)
		}
	}

	struct Package: LinearEncodedPair {
		let first: Content  //Content.wireformat
		let second: TypedSignature  //delegated agent signature
	}

	struct AgentSignatureBody: LinearEncodedQuad {
		static let discriminator = "AnchorReply.AgentSignatureBody"
		let first: String  //discriminator maps 1:1 to the delegation type
		let second: Content
		//injected context for the recipient
		let third: PublicAnchor
		let fourth: DataIdentifier  //MLS groupId
	}

	struct AnchorSignatureBody: LinearEncodedQuintuple {
		static let discriminator = "AnchorReply.AnchorSignatureBody"
		let first: String  //discriminator maps 1:1 to the delegation type
		let second: Data  //Package.wireformat
		let third: TypedKeyMaterial  //sender AnchorPublicKey
		//injected context for the recipient
		let fourth: PublicAnchor
		let fifth: DataIdentifier  //MLS groupId

		init(
			first: String,
			second: Data,
			third: TypedKeyMaterial,
			fourth: PublicAnchor,
			fifth: DataIdentifier
		) {
			self.first = first
			self.second = second
			self.third = third
			self.fourth = fourth
			self.fifth = fifth
		}

		init(
			encodedPackage: Data,
			knownAnchor: AnchorPublicKey,
			recipient: PublicAnchor,
			mlsGroupId: DataIdentifier,
		) {
			self.init(
				first: Self.discriminator,
				second: encodedPackage,
				third: knownAnchor.archive,
				fourth: recipient,
				fifth: mlsGroupId
			)
		}
	}

	public struct Verified {
		public let agent: PublicAnchorAgent
		public let welcome: Welcome
	}
}
