//
//  SignedContent.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 4/23/25.
//

import Foundation

//V2 of SignedObject to facilitate context that is known but not
//transmitted, or condent sent alongside, like the public signing key

public protocol SignableContent {
	init(wireFormat: Data) throws
	var wireFormat: Data { get throws }
}

extension SignableContent {
	typealias SignatureFomatter = @Sendable (Self) throws -> Data
	typealias Signer = @Sendable (Data) throws -> TypedSignature
	typealias Verifier = @Sendable (Data) -> Bool
}

public struct SignedContent<Content: SignableContent> {
	let content: Content
	let signature: TypedSignature

	static var defaultFomatter: Content.SignatureFomatter {
		{ try $0.wireFormat }
	}

	func verified(
		formatter: Content.SignatureFomatter = Self.defaultFomatter,
		verifier: Content.Verifier
	) throws -> Content {
		let verifyBody = try formatter(content)
		guard verifier(verifyBody) else {
			throw ProtocolError.authenticationError
		}

		return content
	}

	init(
		content: Content,
		signer: Content.Signer,
		formatter: Content.SignatureFomatter
	) throws {
		self.content = content
		self.signature = try signer(try formatter(content))
	}

	init(content: Content, signature: TypedSignature) {
		self.content = content
		self.signature = signature
	}
}

extension SignedContent: LinearEncodable where Content: LinearEncodable {}
extension SignedContent: LinearEncodedPair where Content: LinearEncodable {
	public var first: Content { content }
	public var second: TypedSignature { signature }

	public init(first: Content, second: TypedSignature) throws {
		self.init(content: first, signature: second)
	}
}
