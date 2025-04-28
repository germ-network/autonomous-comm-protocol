//
//  AnchorAgent.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 4/25/25.
//

import Foundation

//In parallel of PrivateActiveAnchor, a more complex object wrapping
//the base key that retains the immutable creation state

public struct PrivateAnchorAgent {
	let privateKey: AgentPrivateKey
	public let publicKey: AgentPublicKey

	//immutable creation data
	let anchorPublicKey: AnchorPublicKey
	let attestation: SignedContent<AnchorAttestation>
	let delegation: SignedContent<AnchorDelegation>
	let delegateType: AnchorDelegationType

	init(
		privateKey: AgentPrivateKey,
		anchorPublicKey: AnchorPublicKey,
		attestation: SignedContent<AnchorAttestation>,
		delegation: SignedContent<AnchorDelegation>,
		delegateType: AnchorDelegationType
	) {
		self.privateKey = privateKey
		self.publicKey = privateKey.publicKey
		self.anchorPublicKey = anchorPublicKey
		self.attestation = attestation
		self.delegation = delegation
		self.delegateType = delegateType
	}
}

extension PrivateAnchorAgent {
	public struct Archive: Codable {
		let privateKey: Data  //AgentPrivateKey.typedWireFormat

		//immutable creation data
		let anchorPublicKey: Data
		let attestation: Data  //SignedContent<AnchorAttestation>.wireformat
		let delegation: Data  //SignedContent<AnchorDelegation>.wireformat
		let delegateType: UInt8  // AnchorDelegationType.rawValue
	}

	public init(archive: Archive) throws {
		let privateKey = try AgentPrivateKey(
			archive: .init(wireFormat: archive.privateKey)
		)
		let delegation = try SignedContent<AnchorDelegation>
			.finalParse(archive.delegation)
		assert(privateKey.publicKey == delegation.content.agentKey)

		guard
			let delegateType = AnchorDelegationType(
				rawValue: archive.delegateType
			)
		else {
			throw ProtocolError.unexpected("unexpected type")
		}

		self.init(
			privateKey: privateKey,
			anchorPublicKey: try .init(
				archive: .init(wireFormat: archive.anchorPublicKey)
			),
			attestation: try .finalParse(archive.attestation),
			delegation: delegation,
			delegateType: delegateType
		)
	}

	public var archive: Archive {
		get throws {
			.init(
				privateKey: privateKey.archive.wireFormat,
				anchorPublicKey: anchorPublicKey.wireFormat,
				attestation: try attestation.wireFormat,
				delegation: try delegation.wireFormat,
				delegateType: delegateType.rawValue
			)
		}
	}
}

extension PrivateAnchorAgent {
	func signAsPredecessor(
		_ format: AnchorHandoff.Agent.NewData.PredecessorFormat
	) throws -> TypedSignature {
		try privateKey.signer(try format.wireFormat)
	}

	//	func signAsSuccessor(
	//		_ format: AnchorHandoff.Agent.NewData.PredecessorFormat
	//	) throws -> TypedSignature {
	//		try privateKey.signer(try format.wireFormat)
	//	}
}
