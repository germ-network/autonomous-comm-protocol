//
//  AnchorSuccession.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 5/7/25.
//

import Foundation

//embed this in content signed by the new key
public struct AnchorSuccession: LinearEncodedPair, Sendable {
	static let discriminator = "AnchorSuccession"
	public let first: TypedKeyMaterial  //previous key
	public let second: TypedSignature  //over first + a discriminator

	public init(first: TypedKeyMaterial, second: TypedSignature) {
		self.first = first
		self.second = second
	}

	static func signatureBody(
		predecessor: AnchorPublicKey,
		successor: AnchorPublicKey
	) -> Data {
		discriminator.utf8Data + predecessor.wireFormat + successor.wireFormat
	}
}

extension AnchorPrivateKey {
	func succession(to successor: AnchorPublicKey) throws -> AnchorSuccession {
		.init(
			first: publicKey.archive,
			second: try signer(
				AnchorSuccession.signatureBody(
					predecessor: publicKey,
					successor: successor
				)
			)
		)
	}
}

extension AnchorSuccession? {
	//returns predecessor
	func verify(successor: AnchorPublicKey) throws -> AnchorPublicKey? {
		guard let self else { return nil }
		let presumedPredecessor = try AnchorPublicKey(archive: self.first)

		let signatureBody = AnchorSuccession.signatureBody(
			predecessor: presumedPredecessor,
			successor: successor
		)

		guard
			presumedPredecessor.verifier(
				self.second,
				signatureBody
			)
		else {
			throw ProtocolError.authenticationError
		}
		return presumedPredecessor
	}
}
