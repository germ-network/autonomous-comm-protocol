//
//  AnchorKey+Mock.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 6/7/26.
//

import CommProtocol

extension AnchorPrivateKey {
	public static func mock(algorithm: SigningKeyAlgorithm = .curve25519) -> Self {
		.init(algorithm: algorithm)
	}
}
