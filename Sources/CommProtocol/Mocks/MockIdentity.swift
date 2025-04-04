//
//  MockIdentity.swift
//  CommProtocol
//
//  Created by Anna Mistele on 10/8/24.
//

import CryptoKit

extension IdentityPrivateKey {
	public static func mock() throws -> Self {
		try .init(
			archive: .init(
				typedKey: Curve25519.Signing.PrivateKey()
			))
	}
}

extension IdentityPublicKey {
	public static func mock() throws -> Self {
		try IdentityPrivateKey.mock().publicKey
	}
}
