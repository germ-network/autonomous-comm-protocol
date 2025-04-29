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

public struct PublicAnchorAgent {
	let anchorkey: AnchorPublicKey
	let agentKey: AgentPublicKey

	public init(anchorkey: AnchorPublicKey, agentKey: AgentPublicKey) {
		self.anchorkey = anchorkey
		self.agentKey = agentKey
	}
}

extension PublicAnchorAgent {
	public func verify(
		anchorHandoff: AnchorHandoff,
		mlsUpdateDigest: TypedDigest
	) throws -> AnchorHandoff.Verified {
		let verifiedPackage = try verifyPackage(
			handoff: anchorHandoff,
			mlsUpdateDigest: mlsUpdateDigest
		)

		let content = verifiedPackage.first
		let newAnchor = try verify(newAnchor: content.second)
		let activeAnchor = newAnchor?.publicKey ?? anchorkey

		guard
			activeAnchor
				.typedVerifier(
					verifiedPackage.second,
					try content.activeAnchorBody.wireFormat
				)
		else {
			throw ProtocolError.authenticationError
		}

		let newAgentKey = try AgentPublicKey(
			archive: content.first.first
		)
		guard
			newAgentKey.typedVerifier(
				verifiedPackage.third,
				try content.activeAgentBody.wireFormat
			)
		else {
			throw ProtocolError.authenticationError
		}

		return .init(
			newAnchor: newAnchor,
			newAgent: newAgentKey,
			newAgentUpdate: content.first.second
		)
	}

	private func verify(
		newAnchor: AnchorHandoff.NewAnchor?
	) throws -> PublicAnchor? {
		guard let newAnchor else { return nil }
		let content = newAnchor.first
		guard
			anchorkey.typedVerifier(
				newAnchor.second,
				try content.retiredAnchorBody.wireFormat
			)
		else {
			throw ProtocolError.authenticationError
		}

		let newAnchorKey = try AnchorPublicKey(archive: content.first)

		return .init(
			publicKey: newAnchorKey,
			verified: content.second
		)
	}

	private func verifyPackage(
		handoff: AnchorHandoff,
		mlsUpdateDigest: TypedDigest
	) throws -> AnchorHandoff.Package {
		guard
			agentKey.typedVerifier(
				handoff.first,
				try AnchorHandoff
					.RetiredAgentBody(
						encodedPackage: handoff.second,
						mlsUpdateDigest: mlsUpdateDigest,
						knownAgent: agentKey
					)
					.wireFormat
			)
		else {
			throw ProtocolError.authenticationError
		}

		return try .finalParse(handoff.second)
	}
}
