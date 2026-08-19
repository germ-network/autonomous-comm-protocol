//
//  Curve25519+Extensions.swift
//
//
//  Created by Mark @ Germ on 6/15/24.
//

import Crypto
import Foundation

extension Curve25519.Signing.PrivateKey: PrivateSigningKey {
	public static let encodeAlgorithm: TypedKeyMaterial.Algorithms = .curve25519Signing

	static let signingAlgorithm: SigningKeyAlgorithm = .curve25519
}

extension Curve25519.Signing.PublicKey: PublicSigningKey {
	public static let signingAlgorithm: SigningKeyAlgorithm = .curve25519
}
