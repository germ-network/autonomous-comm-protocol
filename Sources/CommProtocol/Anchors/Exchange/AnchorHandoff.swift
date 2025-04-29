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

			var retiredAnchorBody: RetiredAnchorBody {
				.init(
					first: RetiredAnchorBody.discriminator,
					second: self
				)
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

	public struct Verified {
		public let newAnchor: Bool
		public let agent: PublicAnchorAgent
		public let newAgentUpdate: AgentUpdate
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

	struct RetiredAgentBody: LinearEncodedQuad {
		static let discriminator = "AnchorHandoff.ActiveAgentBody"
		let first: String
		let second: Data  //Package.wireformat
		let third: TypedDigest  //mls update mdigest
		let fourth: TypedKeyMaterial

		init(
			first: String,
			second: Data,
			third: TypedDigest,
			fourth: TypedKeyMaterial
		) {
			self.first = first
			self.second = second
			self.third = third
			self.fourth = fourth
		}

		init(
			encodedPackage: Data,
			mlsUpdateDigest: TypedDigest,
			knownAgent: AgentPublicKey
		) {
			self.first = Self.discriminator
			self.second = encodedPackage
			self.third = mlsUpdateDigest
			self.fourth = knownAgent.id
		}
	}
}
