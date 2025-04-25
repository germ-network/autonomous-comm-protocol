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
}

//the Anchor Public Key is already known
struct AnchorHello {
	let attestation: SignedContent<AnchorAttestation>
	let delegate: SignedContent<IdentitySigned>
	let agentState: SignedContent<AgentSigned>

	//mix in AnchorDelegationType when formatting for signing
	struct IdentitySigned {
		static let discriminator = "AnchorHello.IdentitySigned"
		let agentKey: AgentPublicKey

		func formatForSigning(delegationType: AnchorDelegationType) -> Data {
			Self.discriminator.utf8Data
				+ [delegationType.rawValue]
				+ agentKey.wireFormat
		}
	}

	//no addresses
	//mix in anchor key
	struct AgentSigned {
		static let discriminator = "AnchorHello.AgentSigned"
		let version: SemanticVersion
		let mlsKeyPackages: [Data]

		func formatForSigning(anchorKey: AnchorPublicKey) throws -> Data {
			try Self.discriminator.utf8Data
				+ version.wireFormat
				+ mlsKeyPackages.wireFormat
		}
	}
}

extension AnchorHello: LinearEncodedTriple {
	var first: SignedContent<AnchorAttestation> { attestation }
	var second: SignedContent<IdentitySigned> { delegate }
	var third: SignedContent<AgentSigned> { agentState }

	init(
		first: SignedContent<AnchorAttestation>, second: SignedContent<IdentitySigned>,
		third: SignedContent<AgentSigned>
	) {
		self.attestation = first
		self.delegate = second
		self.agentState = third
	}
}

extension AnchorHello.IdentitySigned: SignableContent {
	init(wireFormat: Data) throws {
		self.agentKey = try .init(wireFormat: wireFormat)
	}
}

extension AnchorHello.IdentitySigned: LinearEncodable {
	public static func parse(_ input: Data) throws -> (AnchorHello.IdentitySigned, Int) {
		let (typedKey, remainder) = try TypedKeyMaterial.parse(input)

		return (
			.init(agentKey: try .init(archive: typedKey)),
			remainder
		)
	}

	var wireFormat: Data { agentKey.wireFormat }
}

extension AnchorHello.AgentSigned: SignableContent {
	init(wireFormat: Data) throws {
		self = try .finalParse(wireFormat)
	}
}

extension AnchorHello.AgentSigned: LinearEncodedPair {
	var first: SemanticVersion { version }
	var second: [Data] { mlsKeyPackages }

	init(first: SemanticVersion, second: [Data]) throws {
		self.version = first
		self.mlsKeyPackages = second
	}
}
