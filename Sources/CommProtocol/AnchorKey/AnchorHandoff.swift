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
	public let first: TypedSignature  //known agent signature
	public let second: Data  //Package.wireformat

	public init(first: TypedSignature, second: Data) {
		self.first = first
		self.second = second
	}
}

extension AnchorHandoff {
	struct Content: LinearEncodedPair {
		let first: NewAgent
		let second: NewAnchor?

		var activeAnchorBody: ActiveAnchorBody {
			.init(
				first: ActiveAnchorBody.discriminator,
				second: self
			)
		}

		var activeAgentBody: ActiveAgentBody {
			.init(
				first: ActiveAgentBody.discriminator,
				second: self
			)
		}
	}

	struct Package: LinearEncodedTriple {
		let first: Content
		let second: TypedSignature  //active anchor signature
		let third: TypedSignature  //new agent signature
	}

	struct NewAnchor: LinearEncodedPair {
		struct Content: LinearEncodedPair {
			let first: TypedKeyMaterial  //AnchorPublicKey
			let second: AnchorAttestation

			init(
				publicKey: AnchorPublicKey,
				attestation: AnchorAttestation
			) {
				self.first = publicKey.archive
				self.second = attestation
			}

			init(first: TypedKeyMaterial, second: AnchorAttestation) throws {
				self.first = first
				self.second = second
			}

		}
		let first: Content
		//if we introduce a new anchor we need the previous anchor to endorse this
		let second: TypedSignature
	}

	struct NewAgent: LinearEncodedPair {
		let first: TypedKeyMaterial
		let second: AgentUpdate

		init(
			publicKey: AgentPublicKey,
			agentUpdate: AgentUpdate
		) {
			self.first = publicKey.id
			self.second = agentUpdate
		}

		init(first: TypedKeyMaterial, second: AgentUpdate) throws {
			self.first = first
			self.second = second
		}
	}

	struct Verified {

	}
}

//signature bodies
extension AnchorHandoff {
	struct RetiredAnchorBody: LinearEncodedPair {
		static let discriminator = "AnchorHandoff.RetiredAnchorBody"
		let first: String
		let second: NewAnchor.Content
	}

	struct ActiveAnchorBody: LinearEncodedPair {
		static let discriminator = "AnchorHandoff.ActiveAnchorBody"
		let first: String
		let second: Content
	}

	struct ActiveAgentBody: LinearEncodedPair {
		static let discriminator = "AnchorHandoff.RetiredAgentBody"
		let first: String
		let second: Content
	}

	struct RetiredAgentBody: LinearEncodedTriple {
		static let discriminator = "AnchorHandoff.ActiveAgentBody"
		let first: String
		let second: Data  //Package.wireformat
		let third: TypedDigest

		init(first: String, second: Data, third: TypedDigest) {
			self.first = first
			self.second = second
			self.third = third
		}

		init(encodedPackage: Data, mlsUpdateDigest: TypedDigest) {
			self.first = Self.discriminator
			self.second = encodedPackage
			self.third = mlsUpdateDigest
		}
	}
}

public struct AnchorHandoffDep {
	let newAnchor: Anchor?
	let newAgent: Agent
}

//MARK: Types
extension AnchorHandoffDep {
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

extension AnchorHandoffDep {
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

extension AnchorHandoffDep.Agent.NewData: LinearEncodedPair {
	public var first: TypedKeyMaterial { anchorDelegation.agentKey.id }
	public var second: AgentUpdate { agentUpdate }

	init(first: First, second: Second, ) throws {
		self.anchorDelegation = .init(agentKey: try .init(archive: first))
		self.agentUpdate = second
	}
}
