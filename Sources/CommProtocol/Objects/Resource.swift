//
//  Resource.swift
//
//
//  Created by Mark @ Germ on 6/18/24.
//

@preconcurrency import CryptoKit
import Foundation

//local representation of the resource
//signed to prevent wire injection of a malicious URI
public struct Resource: Sendable {
	public struct Constants {
		public static let minExpiration = TimeInterval(24 * 3600)
	}

	public let identifier: String  //base64url decodes to digest of the ciphertext
	public let host: String
	public let symmetricKey: SymmetricKey
	public let expiration: RoundedDate

	public init(
		identifier: String,
		host: String,
		symmetricKey: SymmetricKey,
		expiration: Date
	) {
		self.identifier = identifier
		self.host = host
		self.symmetricKey = symmetricKey
		self.expiration = .init(date: expiration)
	}

	init(
		identifier: String,
		host: String,
		symmetricKey: SymmetricKey,
		expiration: RoundedDate
	) {
		self.identifier = identifier
		self.host = host
		self.symmetricKey = symmetricKey
		self.expiration = expiration
	}

	public var url: URL? {
		var urlComponents = URLComponents()
		urlComponents.host = host
		urlComponents.scheme = "https"
		urlComponents.path = "/api/card/fetch/" + identifier
		urlComponents.fragment = symmetricKey.rawRepresentation.base64URLEncodedString()
		return urlComponents.url
	}
}

extension Resource: LinearEncodedQuad {
	public var first: String { identifier }
	public var second: String { host }
	public var third: Data { symmetricKey.dataRepresentation }
	public var fourth: RoundedDate { expiration }

	public init(first: String, second: String, third: Data, fourth: RoundedDate) throws {
		try self.init(
			identifier: first,
			host: second,
			symmetricKey: .init(rawRepresentation: third),
			expiration: fourth
		)
	}
}

extension Resource: Equatable {}
