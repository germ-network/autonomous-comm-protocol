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

public struct AnchorHello: LinearEncodedPair {
	public let first: TypedSignature
	public let second: Data  //Package.wireformat

	public init(first: TypedSignature, second: Data) {
		self.first = first
		self.second = second
	}
}

extension AnchorHello {
	struct Content: LinearEncodedQuad {
		let first: AnchorAttestation
		let second: TypedKeyMaterial  //AgentPublicKey
		let third: SemanticVersion
		let fourth: [Data]  //mlsKeyPackages

		func agentSignatureBody() -> AgentSignatureBody {
			.init(
				first: AnchorHello.AgentSignatureBody.discriminator,
				second: self
			)
		}
	}

	struct Package: LinearEncodedPair {
		let first: Content  //Content.wireformat
		let second: TypedSignature  //delegated agent signature
	}

	struct AgentSignatureBody: LinearEncodedPair {
		static let discriminator = "AnchorHello.AgentSignatureBody"
		let first: String  //discriminator maps 1:1 to the delegation type
		let second: Content
	}

	struct AnchorSignatureBody: LinearEncodedTriple {
		static let discriminator = "AnchorHello.AnchorSignatureBody"
		let first: String  //discriminator maps 1:1 to the delegation type
		let second: Data  //Package.wireformat
		let third: TypedKeyMaterial  //AnchorPublicKey

		init(first: String, second: Data, third: TypedKeyMaterial) {
			self.first = first
			self.second = second
			self.third = third
		}

		init(encodedPackage: Data, knownAnchor: AnchorPublicKey) throws {
			self.init(
				first: Self.discriminator,
				second: encodedPackage,
				third: knownAnchor.archive
			)
		}
	}
}

extension AnchorHello {
	public struct Verified {
		public let agent: PublicAnchorAgent
		public let version: SemanticVersion
		public let mlsKeyPackages: [Data]

		init(
			agent: PublicAnchorAgent,
			version: SemanticVersion,
			mlsKeyPackages: [Data]
		) {
			self.agent = agent
			self.version = version
			self.mlsKeyPackages = mlsKeyPackages
		}

		public struct Archive: Codable {
			public let agent: PublicAnchorAgent.Archive
			public let version: Data
			public let mlsKeyPackages: [Data]
		}

		public var archive: Archive {
			get throws {
				.init(
					agent: agent.archive,
					version: try version.wireFormat,
					mlsKeyPackages: mlsKeyPackages
				)
			}
		}

		public init(archive: Archive) throws {
			self.init(
				agent: try .init(archive: archive.agent),
				version: try .finalParse(archive.version),
				mlsKeyPackages: archive.mlsKeyPackages
			)
		}
	}
}
