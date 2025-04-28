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
		let newAnchor: NewData
		//existing identity signature
		let predecessorSignature: TypedDigest
		//new identity signature, covering the AnchorAttestation, is included
		//in the AnchorHandoff.Anchor.anchorSignature signature

		public struct NewData {
			let publicKey: AnchorPublicKey
			let attestation: AnchorAttestation
		}

		private struct PredecessorFormat: LinearEncodedTriple {
			static let discriminator = "AnchorHandoff.Anchor.PredecessorFormat"
			let first: String
			let second: TypedKeyMaterial  //prececessor
			let third: TypedKeyMaterial  //successor
		}

		func predecessorSigningFormat(predecessor: AnchorPublicKey) throws -> Data {
			try PredecessorFormat(
				first: PredecessorFormat.discriminator,
				second: predecessor.archive,
				third: newAnchor.publicKey.archive
			).wireFormat
		}
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

			let anchorDelegation: AnchorDelegation
			let agentUpdate: AgentUpdate  //semVer, isAppClip, addresses

			private struct PredecessorFormat: LinearEncodedTriple {
				static let discriminator =
					"AnchorHandoff.Agent.NewData.PredecessorFormat"
				let first: String
				let second: TypedKeyMaterial  //predecessor
				let third: TypedKeyMaterial  //successor
			}
			func predecessorSigningFormat(predecessor: AgentPublicKey) throws -> Data {
				try PredecessorFormat(
					first: PredecessorFormat.discriminator,
					second: predecessor.id,
					third: anchorDelegation.agentKey.id
				).wireFormat
			}

			private struct SuccessorFormat: LinearEncodedQuad {
				static let discriminator =
					"AnchorHandoff.Agent.NewData.SuccessorFormat"
				let first: String
				let second: TypedKeyMaterial  //predecessor anchorKey.archive
				let third: Data  //AnchorDelegation.formatForSigning
				let fourth: AgentUpdate
			}
			func successorSigningFormat(knownAgent: AgentPublicKey) throws -> Data {
				try SuccessorFormat(
					first: SuccessorFormat.discriminator,
					second: knownAgent.id,
					third:
						anchorDelegation
						.formatForSigning(delegationType: .steady),
					fourth: agentUpdate
				).wireFormat

			}

			private struct AnchorFormat: LinearEncodedQuad {
				static let discriminator =
					"AnchorHandoff.Agent.NewData.AnchorFormat"
				let first: String
				//previous AnchorPublicKey if differernt
				let second: TypedKeyMaterial?
				let third: TypedKeyMaterial  //new AnchorPublicKey
				let fourth: Data  //anchorDelegation.formatForSigning
			}
			func anchorSigningFormat(
				newAnchorKey: AnchorPublicKey,
				replacing: AnchorPublicKey?
			) throws -> Data {
				try AnchorFormat(
					first: AnchorFormat.discriminator,
					second: replacing?.archive,
					third: newAnchorKey.archive,
					fourth:
						anchorDelegation
						.formatForSigning(delegationType: .steady)
				).wireFormat
			}
		}
	}
}

extension AnchorHandoff.Agent.NewData: LinearEncodedPair {
	public var first: TypedKeyMaterial { anchorDelegation.agentKey.id }
	public var second: AgentUpdate { agentUpdate }

	init(first: First, second: Second, ) throws {
		self.anchorDelegation = .init(agentKey: try .init(archive: first))
		self.agentUpdate = second
	}
}
