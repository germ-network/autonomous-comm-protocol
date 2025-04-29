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
	private let privateKey: AgentPrivateKey
	public let publicKey: AgentPublicKey

	//immutable creation data
	let anchorPublicKey: AnchorPublicKey
	let delegationType: AnchorDelegationType

	var signer: @Sendable (Data) throws -> TypedSignature {
		privateKey.signer
	}

	init(
		privateKey: AgentPrivateKey,
		anchorPublicKey: AnchorPublicKey,
		delegationType: AnchorDelegationType
	) {
		self.privateKey = privateKey
		self.publicKey = privateKey.publicKey
		self.anchorPublicKey = anchorPublicKey
		self.delegationType = delegationType
	}
}

extension PrivateAnchorAgent {
	public struct Archive: Codable {
		let privateKey: Data  //AgentPrivateKey.typedWireFormat

		//immutable creation data
		let anchorPublicKey: Data
		let delegationType: UInt8
	}

	public init(archive: Archive) throws {
		let privateKey = try AgentPrivateKey(
			archive: .init(wireFormat: archive.privateKey)
		)

		guard let delegationType = AnchorDelegationType(rawValue: archive.delegationType)
		else {
			throw ProtocolError.missingOptional("AnchorDelegationType")
		}

		self.init(
			privateKey: privateKey,
			anchorPublicKey: try .init(
				archive: .init(wireFormat: archive.anchorPublicKey)
			),
			delegationType: delegationType
		)
	}

	public var archive: Archive {
		get throws {
			.init(
				privateKey: privateKey.archive.wireFormat,
				anchorPublicKey: anchorPublicKey.wireFormat,
				delegationType: delegationType.rawValue,
			)
		}
	}
}

public struct PublicAnchorAgent {
	public let anchor: PublicAnchor
	public let agentKey: AgentPublicKey
	
	public var anchorKey: AnchorPublicKey { anchor.publicKey }

	public init(anchor: PublicAnchor, agentKey: AgentPublicKey) {
		self.anchor = anchor
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
		let activeAnchor = newAnchor?.publicKey ?? anchor.publicKey

		guard
			activeAnchor
				.verifier(
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
			newAgentKey.verifier(
				verifiedPackage.third,
				try content.activeAgentBody.wireFormat
			)
		else {
			throw ProtocolError.authenticationError
		}

		return .init(
			newAnchor: newAnchor != nil,
			agent: .init(
				anchor: newAnchor ?? anchor,
				agentKey: newAgentKey
			),
			newAgentUpdate: content.first.second
		)
	}

	private func verify(
		newAnchor: AnchorHandoff.NewAnchor?
	) throws -> PublicAnchor? {
		guard let newAnchor else { return nil }
		let content = newAnchor.first
		guard
			anchor.publicKey.verifier(
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
			agentKey.verifier(
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
