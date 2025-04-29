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

public struct AnchorReply {
	struct Content: LinearEncodedQuintuple {
		let first: AnchorAttestation
		let second: TypedKeyMaterial  //AgentPublicKey
		let third: SemanticVersion
		let fourth: UInt32
		let fifth: Date

		func agentSignatureBody(
			mlsWelcomeDigest: TypedDigest
		) -> AgentSignatureBody {
			.init(
				first: AnchorReply.AgentSignatureBody.discriminator,
				second: self,
				third: mlsWelcomeDigest
			)
		}
	}

	struct Package: LinearEncodedPair {
		let first: Content  //Content.wireformat
		let second: TypedSignature  //delegated agent signature
	}
	//MARK: Properties
	public let first: TypedSignature
	public let second: Data  //Package.wireformat

	public init(first: TypedSignature, second: Data) {
		self.first = first
		self.second = second
	}

	struct AgentSignatureBody: LinearEncodedTriple {
		static let discriminator = "AnchorReply.AgentSignatureBody"
		let first: String  //discriminator maps 1:1 to the delegation type
		let second: Content
		let third: TypedDigest
	}

	struct AnchorSignatureBody: LinearEncodedTriple {
		static let discriminator = "AnchorReply.AnchorSignatureBody"
		let first: String  //discriminator maps 1:1 to the delegation type
		let second: Data  //Package.wireformat
		let third: TypedKeyMaterial  //AnchorPublicKey

		init(first: String, second: Data, third: TypedKeyMaterial) {
			self.first = first
			self.second = second
			self.third = third
		}

		init(encodedPackage: Data, knownAnchor: AnchorPublicKey) throws {
			self.init(
				first: Self.discriminator,
				second: encodedPackage,
				third: knownAnchor.archive
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
