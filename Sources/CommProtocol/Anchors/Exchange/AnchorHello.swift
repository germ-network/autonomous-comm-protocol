//
//  AnchorHello.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 4/24/25.
//

import Foundation

//the Anchor Public Key is already known
//repackaging this so we can check signature with known key before unwrapping
//Pattern:
//- Inner content that we are transmitting
//- Signatures constructed from the content, maybe with additional context
//- Wrap those in one data structure signed with the known key
//- Mix in additional context as needed when verifying the outer signature

public struct AnchorHello: LinearEncodedPair, Sendable {
	public let first: TypedSignature
	public let second: Data  //Package.wireformat

	public init(first: TypedSignature, second: Data) {
		self.first = first
		self.second = second
	}
}

extension AnchorHello {
	struct Content: LinearEncodedTriple {
		let first: [AnchorSuccession.Proof]
		let second: AnchorPolicy
		let third: AgentData

		func agentSignatureBody(
			dependentId: DependentIdentity
		) -> AgentSignatureBody {
			.init(
				first: AnchorHello.AgentSignatureBody.discriminator,
				second: dependentId,
				third: self
			)
		}

		//just to add fields
		struct AgentData: LinearEncodedTriple {
			let first: TypedKeyMaterial  //AgentPublicKey
			let second: SemanticVersion
			let third: [Data]  //mlsKeyPackages
		}
	}

	struct Package: LinearEncodedPair {
		let first: Content  //Content.wireformat
		let second: TypedSignature  //delegated agent signature
	}

	struct AgentSignatureBody: LinearEncodedTriple {
		static let discriminator = "AnchorHello.AgentSignatureBody"
		let first: String  //discriminator maps 1:1 to the delegation type
		let second: DependentIdentity
		let third: Content
	}

	struct AnchorSignatureBody: LinearEncodedQuad {
		static let discriminator = "AnchorHello.AnchorSignatureBody"
		let first: String  //discriminator maps 1:1 to the delegation type
		let second: DependentIdentity
		let third: Data  //Package.wireformat
		let fourth: TypedKeyMaterial  //AnchorPublicKey

		init(
			first: String, second: DependentIdentity, third: Data,
			fourth: TypedKeyMaterial
		) {
			self.first = first
			self.second = second
			self.third = third
			self.fourth = fourth
		}

		init(
			dependentId: DependentIdentity,
			encodedPackage: Data,
			knownAnchor: AnchorPublicKey
		) throws {
			self.init(
				first: Self.discriminator,
				second: dependentId,
				third: encodedPackage,
				fourth: knownAnchor.archive
			)
		}
	}
}

extension AnchorHello {
	public struct Verified: Sendable {
		public let agent: PublicAnchorAgent
		public let succession: [AnchorPublicKey]
		public let policy: AnchorPolicy
		public let version: SemanticVersion
		public let mlsKeyPackages: [Data]

		init(
			agent: PublicAnchorAgent,
			succession: [AnchorPublicKey],
			policy: AnchorPolicy,
			version: SemanticVersion,
			mlsKeyPackages: [Data],
		) {
			self.agent = agent
			self.succession = succession
			self.policy = policy
			self.version = version
			self.mlsKeyPackages = mlsKeyPackages
		}

		public struct Archive: Codable, Sendable {
			public let agent: PublicAnchorAgent.Archive
			public let succession: [Data]
			public let version: Data
			public let mlsKeyPackages: [Data]
			public let policy: UInt8
		}

		public var archive: Archive {
			get throws {
				.init(
					agent: agent.archive,
					succession: succession.map { $0.wireFormat },
					version: try version.wireFormat,
					mlsKeyPackages: mlsKeyPackages,
					policy: policy.rawValue
				)
			}
		}

		public init(archive: Archive) throws {
			guard let policy = AnchorPolicy(rawValue: archive.policy) else {
				throw ProtocolError.archiveIncorrect
			}

			self.init(
				agent: try .init(archive: archive.agent),
				succession: archive.succession
					.compactMap { try? .init(wireFormat: $0) },
				policy: policy,
				version: try .finalParse(archive.version),
				mlsKeyPackages: archive.mlsKeyPackages,
			)
		}
	}
}
