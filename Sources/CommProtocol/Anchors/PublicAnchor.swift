//
//  PublicAnchor.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 4/29/25.
//

import Foundation

public struct PublicAnchor: Sendable {
	public let publicKey: AnchorPublicKey
	public let attestation: AnchorAttestation
	public let predecessor: AnchorPublicKey?
}

extension PublicAnchor {
	public struct Archive: Codable {
		let publicKey: Data
		let attestation: AnchorAttestation.Archive
		let predecessor: Data?
	}

	public var archive: Archive {
		.init(
			publicKey: publicKey.wireFormat,
			attestation: attestation.archive,
			predecessor: predecessor?.archive.wireFormat
		)
	}

	public init(archive: Archive) throws {
		self.publicKey = try .init(wireFormat: archive.publicKey)
		self.attestation = try .init(archive: archive.attestation)
		self.predecessor = try .init(optionalArchive: archive.predecessor)
	}
}

extension AnchorPublicKey {
	init?(optionalArchive: Data?) throws {
		guard let optionalArchive else {
			return nil
		}
		self = try .init(wireFormat: optionalArchive)
	}
}

extension AnchorPublicKey? {
	var optionalEncoded: Data? {
		if let self { self.wireFormat } else { nil }
	}
}
