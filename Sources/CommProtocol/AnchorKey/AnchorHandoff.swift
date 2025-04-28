//
//  AnchorHandoff.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 4/25/25.
//

import Foundation

//This is for a handoff for the same AnchorTo
//From one agent to another
//possibly from one anchor key to another
//(the latter facilitates anchor key rotation)

//up to 4 keys in play, each needs to sign off on the others

//Assume starting keys are known, so get coverered by signature but
//don't need to be transmitted

//Optional new identity data
//optional existing identity signature

//Required new agent data
//required new agent signature
//required new? identity signature

public struct AnchorHandoff {
	let newAnchor: Anchor?
	let newAgent: Agent
}

//MARK: Types
extension AnchorHandoff {
	public struct Anchor {
		//new identity data
		let newAnchorData: NewData
		//existing identity signature
		let predecessorSignature: TypedDigest
		//new identity signature, covering the AnchorAttestation, is included
		//in the AnchorHandoff.Anchor.anchorSignature signature

		public struct NewData {
			let publicKey: AnchorPublicKey
			let attestation: AnchorAttestation
		}
	}
}

extension AnchorHandoff {
	enum AnchorDiscriminator: String {
		case predecessorAnchor
		case successorAnchor
	}
	enum AgentDiscriminator: String {
		case predecessorAgent
		case successorAgent
	}
}

extension AnchorHandoff {
	public struct Agent {
		let newAgent: NewData
		let predecessorSignature: TypedDigest
		let successorSignature: TypedDigest
		//covers the previous signature
		let anchorSignature: TypedDigest

		struct NewData {
			static private let discriminator = "AnchorHandoff.Agent.NewData"

			let publicKey: AgentPublicKey
			let agentDelegation: AnchorDelegation
			let agentUpdate: AgentUpdate  //semVer, isAppClip, addresses

			func formatForSigning(
				knownAgent: AgentPublicKey,
				signerRole: AnchorHandoff.AgentDiscriminator
			) throws -> Data {
				try signerRole.rawValue.utf8Data + knownAgent.wireFormat
					+ wireFormat
			}
		}
	}
}

extension AnchorHandoff.Agent.NewData: LinearEncodedTriple {
	public var first: TypedKeyMaterial { publicKey.id }
	public var second: TypedKeyMaterial { agentDelegation.agentKey.id }
	public var third: AgentUpdate { agentUpdate }

	init(first: First, second: Second, third: Third) throws {
		self.publicKey = try .init(archive: first)
		self.agentDelegation = .init(agentKey: try .init(archive: second))
		self.agentUpdate = third
	}
}
