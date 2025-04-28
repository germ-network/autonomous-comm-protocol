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
	//could fetch this but sending it saves us an
	//additional request
	let attestation: SignedContent<AnchorAttestation>
	let delegation: SignedContent<AnchorDelegation>
	let agentState: SignedContent<AgentSigned>

	//no addresses
	//mix in anchor key
	public struct AgentSigned {
		static let discriminator = "AnchorHello.AgentSigned"
		let version: SemanticVersion
		let seqNo: UInt32  //sets initial seqNo
		let sentTime: Date

		private struct Format: LinearEncodedQuad {
			let first: String
			let second: Inner
			let third: TypedKeyMaterial
			let fourth: TypedDigest

			struct Inner: LinearEncodedTriple {
				let first: SemanticVersion
				let second: UInt32
				let third: Date
			}
		}

		func formatForSigning(
			anchorKey: AnchorPublicKey,
			mlsWelcomeDigest: TypedDigest
		) throws -> Data {
			try Format(
				first: Self.discriminator,
				second: .init(
					first: version,
					second: seqNo,
					third: sentTime
				),
				third: anchorKey.archive,
				fourth: mlsWelcomeDigest
			).wireFormat
		}
	}

	public struct Verified {
		public let publicAnchor: PublicAnchor
		public let agentPublicKey: AgentPublicKey
		public let version: SemanticVersion
		public let seqNo: UInt32
		public let sentTime: Date
	}
}

extension AnchorReply: LinearEncodedTriple {
	public var first: SignedContent<AnchorAttestation> { attestation }
	public var second: SignedContent<AnchorDelegation> { delegation }
	public var third: SignedContent<AgentSigned> { agentState }

	public init(
		first: SignedContent<AnchorAttestation>,
		second: SignedContent<AnchorDelegation>,
		third: SignedContent<AgentSigned>
	) {
		self.attestation = first
		self.delegation = second
		self.agentState = third
	}
}

extension AnchorReply.AgentSigned: LinearEncodedTriple {
	public var first: SemanticVersion { version }
	public var second: UInt32 { seqNo }
	public var third: Date { sentTime }

	public init(first: SemanticVersion, second: UInt32, third: Date) {
		self.version = first
		self.seqNo = second
		self.sentTime = third
	}
}

extension AnchorReply.AgentSigned: SignableContent {
	public init(wireFormat: Data) throws {
		self = try .finalParse(wireFormat)
	}
}
