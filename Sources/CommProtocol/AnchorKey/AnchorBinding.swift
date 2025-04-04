//
//  AnchorBinding.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 3/6/25.
//

import Foundation

//we probably don't need to transmit either key, so we just need
//signatures
public struct AnchorIdentityBinding {
	public let anchorSignature: TypedDigest
	public let identitySignature: TypedDigest

	public func formatForSigning(
		anchorKey: AnchorPublicKey,
		identityKey: IdentityPublicKey
	) -> Data {
		Data("AnchorIdentityBinding".utf8) + anchorKey.wireFormat + identityKey.wireFormat
	}
}

extension AnchorIdentityBinding: LinearEncodedPair {
	public var first: TypedDigest { anchorSignature }
	public var second: TypedDigest { identitySignature }

	public init(first: TypedDigest, second: TypedDigest) throws {
		self.init(anchorSignature: first, identitySignature: second)
	}
}
