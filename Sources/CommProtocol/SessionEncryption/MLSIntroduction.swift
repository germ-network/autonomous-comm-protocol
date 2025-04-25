//
//  KeyPackages.swift
//
//
//  Created by Mark @ Germ on 7/2/24.
//

import Foundation

//legacy, we can now use defer to the MLS key package for
//kemPublicKey and suite

//we actually want an additional HPKE key for the basic message
public struct MLSIntroduction: Sendable, Equatable {
	public let suite: SessionEncryptionSuites
	//    public let clientId: Data
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
