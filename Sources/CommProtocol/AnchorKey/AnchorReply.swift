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
	//	let agentState: SignedContent<AgentSigned>

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
	}
}
