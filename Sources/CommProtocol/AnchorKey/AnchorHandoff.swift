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
		let predecessorSignature: TypedSignature
		//new identity signature, covering the AnchorAttestation, is included
		//in the AnchorHandoff.Anchor.anchorSignature signature

		public struct NewData {
			let publicKey: AnchorPublicKey
			let attestation: AnchorAttestation
		}

		struct PredecessorFormat: LinearEncodedTriple {
			static let discriminator = "AnchorHandoff.Anchor.PredecessorFormat"
			let first: String
			let second: TypedKeyMaterial  //prececessor
			let third: TypedKeyMaterial  //successor
		}

		func predecessorSigningFormat(predecessor: AnchorPublicKey) throws
			-> PredecessorFormat
		{
			PredecessorFormat(
				first: PredecessorFormat.discriminator,
				second: predecessor.archive,
				third: newAnchor.publicKey.archive
			)
		}
	}
}

extension AnchorHandoff {
	public struct Agent {
		let newAgent: NewData
		let predecessorSignature: TypedSignature
		let successorSignature: TypedSignature
		//covers the previous signature
		let anchorSignature: TypedSignature

		struct NewData {
			static private let discriminator = "AnchorHandoff.Agent.NewData"

			let anchorDelegation: AnchorDelegation
			let agentUpdate: AgentUpdate  //semVer, isAppClip, addresses

			struct PredecessorFormat: LinearEncodedTriple {
				static let discriminator =
					"AnchorHandoff.Agent.NewData.PredecessorFormat"
				let first: String
				let second: TypedKeyMaterial  //predecessor
				let third: TypedKeyMaterial  //successor
			}
			func predecessorSigningFormat(
				predecessor: AgentPublicKey
			) -> PredecessorFormat {
				.init(
					first: PredecessorFormat.discriminator,
					second: predecessor.id,
					third: anchorDelegation.agentKey.id
				)
			}

			struct SuccessorFormat: LinearEncodedQuad {
				static let discriminator =
					"AnchorHandoff.Agent.NewData.SuccessorFormat"
				let first: String
				let second: TypedKeyMaterial  //predecessor anchorKey.archive
				//AnchorDelegation.formatForSigning
				let third: AnchorDelegation.Format
				let fourth: AgentUpdate
			}
			func successorSigningFormat(knownAgent: AgentPublicKey) -> SuccessorFormat {
				.init(
					first: SuccessorFormat.discriminator,
					second: knownAgent.id,
					third: anchorDelegation.formatForSigning(
						delegationType: .steady),
					fourth: agentUpdate
				)

			}

			struct AnchorFormat: LinearEncodedQuad {
				static let discriminator =
					"AnchorHandoff.Agent.NewData.AnchorFormat"
				let first: String
				//previous AnchorPublicKey if differernt
				let second: TypedKeyMaterial?
				let third: AnchorAttestation.Format
				//anchorDelegation.formatForSigning
				let fourth: AnchorDelegation.Format
			}
			func anchorSigningFormat(
				newAnchorKey: AnchorPublicKey,
				anchorAttestation: AnchorAttestation,
				replacing: AnchorPublicKey?
			) -> AnchorFormat {
				.init(
					first: AnchorFormat.discriminator,
					second: replacing?.archive,
					third:
						anchorAttestation
						.formatForSigning(anchorKey: newAnchorKey),
					fourth: anchorDelegation.formatForSigning(
						delegationType: .steady)
				)
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
