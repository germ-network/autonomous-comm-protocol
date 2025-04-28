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

	func formatForSigning(delegationType: AnchorDelegationType) -> Data {
		Self.discriminator.utf8Data
			+ [delegationType.rawValue]
			+ agentKey.wireFormat
	}
}

extension AnchorDelegation: SignableContent {
	public init(wireFormat: Data) throws {
		self.agentKey = try .init(wireFormat: wireFormat)
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
public struct AnchorHello {
	let attestation: SignedContent<AnchorAttestation>
	let delegate: SignedContent<AnchorDelegation>
	let agentState: SignedContent<AgentSigned>

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
		public let publicAnchor: PublicAnchor
		public let agentPublicKey: AgentPublicKey
		public let version: SemanticVersion
		public let mlsKeyPackages: [Data]
	}
}

extension AnchorHello: LinearEncodedTriple {
	public var first: SignedContent<AnchorAttestation> { attestation }
	public var second: SignedContent<AnchorDelegation> { delegate }
	public var third: SignedContent<AgentSigned> { agentState }

	public init(
		first: SignedContent<AnchorAttestation>,
		second: SignedContent<AnchorDelegation>,
		third: SignedContent<AgentSigned>
	) {
		self.attestation = first
		self.delegate = second
		self.agentState = third
	}
}

extension AnchorHello.AgentSigned: SignableContent {
	public init(wireFormat: Data) throws {
		self = try .finalParse(wireFormat)
	}
}

extension AnchorHello.AgentSigned: LinearEncodedPair {
	public var first: SemanticVersion { version }
	public var second: [Data] { mlsKeyPackages }

	public init(first: SemanticVersion, second: [Data]) {
		self.version = first
		self.mlsKeyPackages = second
	}
}
