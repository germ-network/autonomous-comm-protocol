//
//  SessionEncryptionSuites.swift
//  CommProtocol
//
//  Created by Mark Xue on 8/19/24.
//

import Foundation

public enum SessionEncryptionSuites: UInt8, Equatable, Sendable, CaseIterable, Codable {
	case mlsCurve25519ChaChaPoly = 1

	//notice: unused
	//match the RFC 9420 cipher suite
	var fixedWidth: Data {
		switch self {
		case .mlsCurve25519ChaChaPoly: Data([0x0, 0x03])
		}
	}

	init(fixedWidth: Data) throws {
		guard fixedWidth.count == 2,
			let first = fixedWidth.first,
			let second = fixedWidth.last
		else {
			throw ProtocolError.archiveIncorrect
		}
		switch (first, second) {
		case (0, 3): self = .mlsCurve25519ChaChaPoly
		default: throw ProtocolError.archiveIncorrect
		}
	}
}

extension SessionEncryptionSuites: LinearEncodable {
	static public func parse(_ input: Data) throws(LinearEncodingError) -> (
		SessionEncryptionSuites,
		Int
	) {
		guard let prefix = input.first,
			let suite = SessionEncryptionSuites(rawValue: prefix)
		else {
			throw LinearEncodingError.unexpectedData
		}
		return (suite, 1)
	}

	public var wireFormat: Data {
		.init([rawValue])
	}
}

extension SessionEncryptionSuites {
	var keyMaterialType: TypedKeyMaterial.Algorithms {
		switch self {
		case .mlsCurve25519ChaChaPoly:
			.hpkeEncapCurve25519Sha256ChachaPoly
		}
	}

	init(keyMaterialType: TypedKeyMaterial.Algorithms) throws {
		switch keyMaterialType {
		case .hpkeEncapCurve25519Sha256ChachaPoly:
			self = .mlsCurve25519ChaChaPoly
		default: throw ProtocolError.archiveIncorrect
		}
	}
}
