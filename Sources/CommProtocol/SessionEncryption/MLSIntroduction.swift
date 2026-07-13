//
//  KeyPackages.swift
//
//
//  Created by Mark @ Germ on 7/2/24.
//

import Foundation

///One entry in a card offer's key choices.
///
///This is a legacy wire format: `suite` and `kemPublicKeyData` describe a classical MLS
///cipher suite, and only `encodedKeyPackage` is opaque. A post-quantum (TwoMLSPQ) key
///package is carried inside `encodedKeyPackage` of an otherwise-classical entry (see
///`postQuantumShim`), so it is indistinguishable on the wire from a classical entry.
///That is deliberate: already-deployed parsers accept a card that offers both, because
///every entry is a well-formed legacy entry. PQ-capable consumers detect the PQ entry by
///parsing its `encodedKeyPackage`. For a PQ entry the wrapper carries no PQ signal and
///`kemPublicKeyData` is unused — the self-contained key package supplies its own transport
///keys; the field persists only because the legacy wire shape encodes a fixed-width value
///there. An honest, suite-typed card format is left for a future replacement.
///
///Publishers order key choices most-compatible first: the classical entry stays at
///index 0. Existing consumers select the first entry whose wrapper `suite` they
///recognize, and the shim reuses the classical suite, so a mis-ordered card would be
///mis-selected by already-deployed clients. Ordering is load-bearing, not cosmetic.
public struct MLSIntroduction: Sendable, Equatable {
	public let suite: SessionEncryptionSuites
	//header encryption for the welcome stream
	public let kemPublicKeyData: Data
	public let encodedKeyPackage: Data  // Message.toBytes

	public init(
		suite: SessionEncryptionSuites,
		kemPublicKeyData: Data,
		encodedKeyPackage: Data
	) {
		self.suite = suite
		self.kemPublicKeyData = kemPublicKeyData
		self.encodedKeyPackage = encodedKeyPackage
	}
}

extension MLSIntroduction {
	///Carry a post-quantum (TwoMLSPQ) key package in the legacy card offer. The entry is
	///wire-indistinguishable from a classical one — the suite and kem key keep their
	///classical values, and the self-contained PQ key package rides in `encodedKeyPackage`
	///— so pre-upgrade parsers accept a card that offers it. This is the single migration
	///point when a PQ-native card format replaces this one.
	///
	///`kemPublicKeyData` is unused by PQ consumers (the key package carries its own
	///transport keys); it is present only to satisfy the fixed-width wire shape, so it must
	///still be a valid 32-byte value.
	public static func postQuantumShim(
		kemPublicKeyData: Data,
		encodedKeyPackage: Data
	) -> MLSIntroduction {
		.init(
			suite: .mlsCurve25519ChaChaPoly,
			kemPublicKeyData: kemPublicKeyData,
			encodedKeyPackage: encodedKeyPackage
		)
	}
}

extension MLSIntroduction: LinearEncodedPair {
	public var first: TypedKeyMaterial {
		get throws {
			try .init(
				encapAlgorithm: suite.keyMaterialType,
				data: kemPublicKeyData
			)
		}
	}

	public var second: Data { encodedKeyPackage }

	public init(first: TypedKeyMaterial, second: Data) throws {
		self.init(
			suite: try .init(keyMaterialType: first.algorithm),
			kemPublicKeyData: first.keyData,
			encodedKeyPackage: second
		)
	}
}

public typealias SessionIntroductionChoices = [MLSIntroduction]
