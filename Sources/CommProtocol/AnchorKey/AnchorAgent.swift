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

	init(
		privateKey: AgentPrivateKey,
		anchorPublicKey: AnchorPublicKey,
	) {
		self.privateKey = privateKey
		self.publicKey = privateKey.publicKey
		self.anchorPublicKey = anchorPublicKey
	}
}

extension PrivateAnchorAgent {
	public struct Archive: Codable {
		let privateKey: Data  //AgentPrivateKey.typedWireFormat

		//immutable creation data
		let anchorPublicKey: Data
	}

	public init(archive: Archive) throws {
		let privateKey = try AgentPrivateKey(
			archive: .init(wireFormat: archive.privateKey)
		)

		self.init(
			privateKey: privateKey,
			anchorPublicKey: try .init(
				archive: .init(wireFormat: archive.anchorPublicKey)
			),
		)
	}

	public var archive: Archive {
		get throws {
			.init(
				privateKey: privateKey.archive.wireFormat,
				anchorPublicKey: anchorPublicKey.wireFormat,
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
