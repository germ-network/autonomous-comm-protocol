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
	let delegate: SignedContent<AnchorDelegation>
	let agentState: SignedContent<AgentSigned>

	//no addresses
	//mix in anchor key
	public struct AgentSigned {
		static let discriminator = "AnchorHello.AgentSigned"
		let version: SemanticVersion
		let mlsWelcome: Data
		let seqNo: UInt32  //sets initial seqNo
		let sentTime: Date

		func formatForSigning(anchorKey: AnchorPublicKey) throws -> Data {
			try Self.discriminator.utf8Data
				+ version.wireFormat
				+ mlsWelcome.wireFormat
		}
	}

	public struct Verified {
		public let publicAnchor: PublicAnchor
		public let agentPublicKey: AgentPublicKey
		public let version: SemanticVersion
		public let mlsWelcome: Data
		public let seqNo: UInt32
		public let sentTime: Date
	}
}

extension AnchorReply: LinearEncodedTriple {
	public var first: SignedContent<AnchorAttestation> { attestation }
	public var second: SignedContent<AnchorDelegation> { delegate }
	public var third: SignedContent<AgentSigned> { agentState }

	public init(
		first: SignedContent<AnchorAttestation>,
		second: SignedContent<AnchorDelegation>,
		third: SignedContent<AgentSigned>
	) {
		self.attestation = first
		self.delegate = second
		self.agentState = third
	}
}

extension AnchorReply.AgentSigned: LinearEncodedQuad {
	public var first: SemanticVersion { version }
	public var second: Data { mlsWelcome }
	public var third: UInt32 { seqNo }
	public var fourth: Date { sentTime }

	public init(first: SemanticVersion, second: Data, third: UInt32, fourth: Date) {
		self.version = first
		self.mlsWelcome = second
		self.seqNo = third
		self.sentTime = fourth
	}
}

extension AnchorReply.AgentSigned: SignableContent {
	public init(wireFormat: Data) throws {
		self = try .finalParse(wireFormat)
	}
}
