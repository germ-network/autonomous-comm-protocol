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

		// MARK: v2 — opaque digest bodies

		func activeAnchorBodyV2(
			groupContext: Data,
			knownAgent: AgentPublicKey,
		) throws -> ActiveAnchorBodyV2 {
			.init(
				first: ActiveAnchorBodyV2.discriminator,
				second: self,
				third: groupContext,
				fourth: knownAgent.id
			)
		}

		func activeAgentBodyV2(
			groupContext: Data,
			mlsUpdateDigest: Data,
			knownAgent: AgentPublicKey,
		) throws -> ActiveAgentBodyV2 {
			.init(
				first: ActiveAgentBodyV2.discriminator,
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
	// The v1 bodies. Their digest fields are `TypedDigest`, so this package must be able to
	// NAME the hash a peer used — which is why v2 exists (see below).
	//
	// KNOWN-SWAPPED DISCRIMINATORS, DELIBERATELY FROZEN. `ActiveAgentBody` carries the string
	// "AnchorHandoff.RetiredAgentBody" and vice versa. This is a labeling bug, not a security
	// one: domain separation needs the committed strings to be DISTINCT, not correctly named,
	// and they are distinct — so no signature can be replayed across contexts even when one key
	// signs both body types across successive rotations. DO NOT "fix" these in place: live
	// relationships have signatures committed over them, and renaming would silently fail every
	// verification. They retire with the v1 bodies. The v2 bodies below carry the corrected
	// names.
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

	// MARK: - v2 bodies: opaque digests
	//
	// Identical in shape to v1, with the digest fields as length-framed `Data`. The point is
	// ownership: a digest's algorithm is a facet of the MLS backend's cipher suite, so naming it
	// here (`DigestTypes`) meant a backend could not adopt a new suite until this package
	// released a matching case. These bodies commit to whatever bytes the caller supplies and
	// never interpret them — the caller's own self-describing encoding travels INSIDE the value,
	// so cross-era signatures stay unambiguous without this package knowing the eras.
	//
	// This is safe because a verifier never parses a digest off the wire: it rebuilds the body
	// from a locally derived reference digest and checks the signature against that. Agreement on
	// the algorithm is enforced where the session is established, not here.
	//
	// DISCRIMINATORS: corrected names, `.v2`-suffixed. The suffix is not decoration — the plain
	// corrected strings are UNAVAILABLE, because v1 has them live on each other's structs (see
	// the frozen-swap note above). Reusing one would put two different structures under one
	// committed string across the union of live body types, which is exactly the distinctness
	// that domain separation rests on. `ActiveAnchorBodyV2` takes the suffix too, though its name
	// was never swapped: its ENCODING differs from v1's, and keeping discriminator↔encoding 1:1
	// is what stops this bug class from recurring.
	struct ActiveAnchorBodyV2: LinearEncodedQuad {
		static let discriminator = "AnchorHandoff.ActiveAnchorBody.v2"
		let first: String
		let second: Content
		let third: Data  //group context, opaque
		let fourth: TypedKeyMaterial  //knownAgent
	}

	struct ActiveAgentBodyV2: LinearEncodedQuintuple {
		static let discriminator = "AnchorHandoff.ActiveAgentBody.v2"
		let first: String
		let second: Content
		let third: Data  //group context, opaque
		let fourth: Data  //mls update digest, opaque
		let fifth: TypedKeyMaterial  //knownAgent
	}

	struct RetiredAgentBodyV2: LinearEncodedQuad {
		static let discriminator = "AnchorHandoff.RetiredAgentBody.v2"
		let first: String
		let second: Data  //Package.wireformat
		let third: Data  //mls update digest, opaque
		let fourth: TypedKeyMaterial  //knownAgent

		init(
			first: String,
			second: Data,
			third: Data,
			fourth: TypedKeyMaterial
		) {
			self.first = first
			self.second = second
			self.third = third
			self.fourth = fourth
		}

		init(
			encodedPackage: Data,
			mlsUpdateDigest: Data,
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
