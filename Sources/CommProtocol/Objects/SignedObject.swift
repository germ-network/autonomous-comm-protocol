//
//  SignableObject.swift
//
//
//  Created by Mark @ Germ on 6/16/24.
//

import CryptoKit
import Foundation

public struct SignedObject<Content: LinearEncodable> {
	public let content: Content
	let signature: TypedSignature
}

extension SignedObject: Sendable where Content: Sendable {}
extension SignedObject: Equatable where Content: Equatable {}

extension SignedObject: LinearEncodedPair {
	public var first: Content { content }
	public var second: TypedSignature { signature }

	public init(first: Content, second: TypedSignature) throws {
		self.init(content: first, signature: second)
	}

}

//like TypedKeyMaterial, prepend a byte that indicates length of the body
public struct TypedSignature: DefinedWidthBinary, Sendable, Equatable {
	public typealias Prefix = SigningKeyAlgorithm
	let signingAlgorithm: SigningKeyAlgorithm
	let signature: Data

	public var wireFormat: Data {
		[signingAlgorithm.rawValue] + signature
	}

	public init(prefix: SigningKeyAlgorithm, checkedData: Data) throws(LinearEncodingError) {
		guard prefix.contentByteSize == checkedData.count else {
			throw .incorrectDataLength
		}
		self.init(signingAlgorithm: prefix, signature: checkedData)
	}

	init(signingAlgorithm: SigningKeyAlgorithm, signature: Data) {
		self.signingAlgorithm = signingAlgorithm
		self.signature = signature
	}
}
