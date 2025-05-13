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

public struct AnchorReply: LinearEncodedPair {
	public let first: TypedSignature
	public let second: Data  //Package.wireformat

	public init(first: TypedSignature, second: Data) {
		self.first = first
		self.second = second
	}
}

extension AnchorReply {
	struct Content: LinearEncodedQuintuple {
		let first: AnchorAttestation  //sender
		let second: TypedKeyMaterial  //AgentPublicKey
		let third: SemanticVersion
		let fourth: UInt32  //seqNo
		let fifth: Date  //date

		func agentSignatureBody(
			mlsWelcomeDigest: TypedDigest,
			recipient: PublicAnchor
		) -> AgentSignatureBody {
			.init(
				first: AnchorReply.AgentSignatureBody.discriminator,
				second: self,
				third: mlsWelcomeDigest,
				fourth: recipient
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
		let third: TypedDigest  //mlsWelcomeDigest
		//injected context for the recipient
		let fourth: PublicAnchor
	}

	struct AnchorSignatureBody: LinearEncodedQuad {
		static let discriminator = "AnchorReply.AnchorSignatureBody"
		let first: String  //discriminator maps 1:1 to the delegation type
		let second: Data  //Package.wireformat
		let third: TypedKeyMaterial  //sender AnchorPublicKey
		//injected context for the recipient
		let fourth: PublicAnchor

		init(
			first: String,
			second: Data,
			third: TypedKeyMaterial,
			fourth: PublicAnchor
		) {
			self.first = first
			self.second = second
			self.third = third
			self.fourth = fourth
		}

		init(
			encodedPackage: Data,
			knownAnchor: AnchorPublicKey,
			recipient: PublicAnchor
		) {
			self.init(
				first: Self.discriminator,
				second: encodedPackage,
				third: knownAnchor.archive,
				fourth: recipient
			)
		}
	}

	public struct Verified {
		public let agent: PublicAnchorAgent
		public let version: SemanticVersion
		public let seqNo: UInt32
		public let sentTime: Date
	}
}
