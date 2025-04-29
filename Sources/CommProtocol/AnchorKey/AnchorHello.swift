//
//  AnchorDelegation.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 4/24/25.
//

import Foundation

//mix this in as appropriate
enum AnchorDelegationType: UInt8 {
	case hello
	case reply
	case steady
	//messaging - same as reply?
}

public struct AnchorDelegation {
	static let discriminator = "AnchorDelegation"
	let agentKey: AgentPublicKey
	//we don't transmit the type as it's expected in context, but is baked
	//into the signed body

	struct Format: LinearEncodedTriple {
		let first: String
		let second: UInt8
		let third: TypedKeyMaterial
	}

	func formatForSigning(delegationType: AnchorDelegationType) -> Format {
		.init(
			first: Self.discriminator,
			second: delegationType.rawValue,
			third: agentKey.id
		)
	}
}

extension AnchorDelegation: LinearEncodable {
	public static func parse(_ input: Data) throws -> (AnchorDelegation, Int) {
		let (typedKey, remainder) = try TypedKeyMaterial.parse(input)

		return (
			.init(agentKey: try .init(archive: typedKey)),
			remainder
		)
	}

	public var wireFormat: Data { agentKey.wireFormat }
}

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

	public struct Verified {
		public let publicAnchor: PublicAnchor
		public let agentPublicKey: AgentPublicKey
		public let version: SemanticVersion
		public let mlsKeyPackages: [Data]
	}
}
