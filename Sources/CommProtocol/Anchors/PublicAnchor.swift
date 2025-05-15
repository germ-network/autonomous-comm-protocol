//
//  PublicAnchor.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 4/29/25.
//

import Foundation

public struct PublicAnchor: Sendable {
	public let publicKey: AnchorPublicKey
	public let attestation: DependentIdentity
}

extension PublicAnchor {
	public struct Archive: Codable {
		let publicKey: Data
		let attestation: DependentIdentity.Archive
	}

	public var archive: Archive {
		.init(
			publicKey: publicKey.wireFormat,
			attestation: attestation.archive,
		)
	}

	public init(archive: Archive) throws {
		self.publicKey = try .init(wireFormat: archive.publicKey)
		self.attestation = try .init(archive: archive.attestation)
	}
}

extension PublicAnchor: LinearEncodedPair {
	public var first: TypedKeyMaterial { publicKey.archive }
	public var second: DependentIdentity { attestation }

	public init(first: First, second: Second) throws {
		self.init(
			publicKey: try .init(archive: first),
			attestation: second
		)
	}
}
