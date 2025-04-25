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
public struct AnchorHello {
	let attestation: SignedContent<AnchorAttestation>
	let delegate: SignedContent<IdentitySigned>
	let agentState: SignedContent<AgentSigned>

	//mix in AnchorDelegationType when formatting for signing
	public struct IdentitySigned {
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
	public struct AgentSigned {
		static let discriminator = "AnchorHello.AgentSigned"
		let version: SemanticVersion
		let mlsKeyPackages: [Data]

		func formatForSigning(anchorKey: AnchorPublicKey) throws -> Data {
			try Self.discriminator.utf8Data
				+ version.wireFormat
				+ mlsKeyPackages.wireFormat
		}
	}

	public struct Verified {
		let publicAnchor: PublicAnchor
		let agentPublicKey: AgentPublicKey
		let version: SemanticVersion
		let mlsKeyPackages: [Data]
	}
}

extension AnchorHello: LinearEncodedTriple {
	public var first: SignedContent<AnchorAttestation> { attestation }
	public var second: SignedContent<IdentitySigned> { delegate }
	public var third: SignedContent<AgentSigned> { agentState }

	public init(
		first: SignedContent<AnchorAttestation>, second: SignedContent<IdentitySigned>,
		third: SignedContent<AgentSigned>
	) {
		self.attestation = first
		self.delegate = second
		self.agentState = third
	}
}

extension AnchorHello.IdentitySigned: SignableContent {
	public init(wireFormat: Data) throws {
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

	public var wireFormat: Data { agentKey.wireFormat }
}

extension AnchorHello.AgentSigned: SignableContent {
	public init(wireFormat: Data) throws {
		self = try .finalParse(wireFormat)
	}
}

extension AnchorHello.AgentSigned: LinearEncodedPair {
	public var first: SemanticVersion { version }
	public var second: [Data] { mlsKeyPackages }

	public init(first: SemanticVersion, second: [Data]) throws {
		self.version = first
		self.mlsKeyPackages = second
	}
}
