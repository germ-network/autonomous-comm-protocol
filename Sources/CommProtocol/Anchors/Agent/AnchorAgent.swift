//
//  AnchorAgent.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 4/25/25.
//

import Foundation

//In parallel of PrivateActiveAnchor, a more complex object wrapping
//the base key that retains the immutable creation state

public struct PrivateAnchorAgent: Sendable {
	public let privateKey: AgentPrivateKey
	public let publicKey: AgentPublicKey

	//immutable creation data
	public let source: Source

	var signer: @Sendable (Data) throws -> TypedSignature {
		privateKey.signer
	}

	public init(
		privateKey: AgentPrivateKey,
		source: Source
	) {
		self.privateKey = privateKey
		self.publicKey = privateKey.publicKey
		self.source = source
	}
}

extension PrivateAnchorAgent {
	public struct Archive: Codable {
		public let privateKey: Data  //AgentPrivateKey.typedWireFormat

		//immutable creation data
		let source: Source.Archive
	}

	public init(archive: Archive) throws {
		self.init(
			privateKey: try .init(
				archive: .init(wireFormat: archive.privateKey)
			),
			source: try .init(archive: archive.source)
		)
	}

	public var archive: Archive {
		get throws {
			.init(
				privateKey: privateKey.archive.wireFormat,
				source: try source.archive
			)
		}
	}
}

public struct PublicAnchorAgent: Sendable, Equatable, Hashable {
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
		context: TypedDigest,
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
					try content.activeAnchorBody(
						groupContext: context,
						knownAgent: agentKey
					).wireFormat
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
				try content
					.activeAgentBody(
						groupContext: context,
						mlsUpdateDigest: mlsUpdateDigest,
						knownAgent: agentKey
					).wireFormat
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
		let newAnchorKey = try AnchorPublicKey(archive: newAnchor.first)

		guard
			anchor.publicKey.verifier(
				newAnchor.second,
				try AnchorSuccession
					.signatureBody(
						attestation: anchor.attestation,
						predecessor: anchor.publicKey,
						successor: newAnchorKey
					)
			)
		else {
			throw ProtocolError.authenticationError
		}

		return .init(
			publicKey: newAnchorKey,
			attestation: anchor.attestation
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

extension PublicAnchorAgent {
	public struct Archive: Codable, Hashable, Sendable {
		let anchor: PublicAnchor.Archive
		let agent: Data
	}

	public var archive: Archive {
		.init(anchor: anchor.archive, agent: agentKey.wireFormat)
	}

	public init(archive: Archive) throws {
		self.anchor = try .init(archive: archive.anchor)
		self.agentKey = try .init(wireFormat: archive.agent)
	}
}
