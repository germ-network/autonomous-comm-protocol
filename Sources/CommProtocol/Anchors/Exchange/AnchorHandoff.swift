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

public struct AnchorHandoff: LinearEncodedPair, Equatable, Sendable {
	public let first: TypedSignature  //known agent signature
	public let second: Data  //Package.wireformat

	public init(first: TypedSignature, second: Data) {
		self.first = first
		self.second = second
	}
}

extension AnchorHandoff {
	public struct Content: LinearEncodedPair, Sendable {
		public let first: NewAgent
		public let second: NewAnchor?

		public init(first: NewAgent, second: NewAnchor?) {
			self.first = first
			self.second = second
		}

		func activeAnchorBody(
			groupContext: TypedDigest,
			knownAgent: AgentPublicKey,
		) throws -> ActiveAnchorBody {
			.init(
				first: ActiveAnchorBody.discriminator,
				second: self,
				third: groupContext,
				fourth: knownAgent.id

			)
		}

		func activeAgentBody(
			groupContext: TypedDigest,
			mlsUpdateDigest: TypedDigest,
			knownAgent: AgentPublicKey,
		) throws -> ActiveAgentBody {
			.init(
				first: ActiveAgentBody.discriminator,
				second: self,
				third: groupContext,
				fourth: mlsUpdateDigest,
				fifth: knownAgent.id
			)
		}
	}

	public struct Package: LinearEncodedTriple {
		public let first: Content
		public let second: TypedSignature  //active anchor signature
		public let third: TypedSignature  //new agent signature

		public init(
			first: Content,
			second: TypedSignature,
			third: TypedSignature
		) {
			self.first = first
			self.second = second
			self.third = third
		}
	}

	public struct NewAnchor: LinearEncodedPair, Sendable {
		public let first: TypedKeyMaterial
		//if we introduce a new anchor we need the previous anchor to endorse this
		//signature from AnchorSuccession.signatureBody
		public let second: TypedSignature

		public init(first: TypedKeyMaterial, second: TypedSignature) {
			self.first = first
			self.second = second
		}
	}

	public struct NewAgent: LinearEncodedPair, Sendable {
		public let first: TypedKeyMaterial
		public let second: AgentUpdate

		init(
			publicKey: AgentPublicKey,
			agentUpdate: AgentUpdate
		) {
			self.first = publicKey.id
			self.second = agentUpdate
		}

		public init(first: TypedKeyMaterial, second: AgentUpdate) throws {
			self.first = first
			self.second = second
		}
	}

	public struct Verified: Sendable, Equatable, Hashable {
		public let newAnchor: Bool
		public let agent: PublicAnchorAgent
		public let newAgentUpdate: AgentUpdate
	}
}

//signature bodies
extension AnchorHandoff {
	struct ActiveAnchorBody: LinearEncodedQuad {
		static let discriminator = "AnchorHandoff.ActiveAnchorBody"
		let first: String
		let second: Content
		let third: TypedDigest  //group context, usually the groupId
		let fourth: TypedKeyMaterial  //knownAgent
	}

	struct ActiveAgentBody: LinearEncodedQuintuple {
		static let discriminator = "AnchorHandoff.RetiredAgentBody"
		let first: String
		let second: Content
		let third: TypedDigest  //group context, usually the groupId
		let fourth: TypedDigest  //mls update digest
		let fifth: TypedKeyMaterial  //knownAgent
	}

	struct RetiredAgentBody: LinearEncodedQuad {
		static let discriminator = "AnchorHandoff.ActiveAgentBody"
		let first: String
		let second: Data  //Package.wireformat
		let third: TypedDigest  //mls update digest
		let fourth: TypedKeyMaterial  //knownAgent

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

extension AnchorHandoff.Verified {
	public struct Archive: Codable, Hashable, Sendable {
		public let newAnchor: Bool
		public let agent: PublicAnchorAgent.Archive
		public let newAgentUpdate: Data  //AgentUpdate.wireformat
	}

	public var archive: Archive {
		get throws {
			.init(
				newAnchor: newAnchor,
				agent: agent.archive,
				newAgentUpdate: try newAgentUpdate.wireFormat
			)
		}
	}

	public init(archive: Archive) throws {
		self.init(
			newAnchor: archive.newAnchor,
			agent: try .init(archive: archive.agent),
			newAgentUpdate: try .finalParse(archive.newAgentUpdate)
		)
	}
}
