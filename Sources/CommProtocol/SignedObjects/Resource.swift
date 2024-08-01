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
    public let expiration: Date

    public init(
        identifier: String,
        host: String,
        symmetricKey: SymmetricKey,
        expiration: Date
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

extension Resource: LinearEncodable {
    public static func parse(_ input: Data) throws -> (Resource, Int) {
        let (id, host, keyData, expiration, consumed) = try LinearEncoder.decode(
            String.self,
            String.self,
            DeclaredWidthData.self,
            Date.self,
            input: input
        )

        let result = Resource(
            identifier: id,
            host: host,
            symmetricKey: .init(data: keyData.body),
            expiration: expiration
        )

        return (result, consumed)
    }

    public var wireFormat: Data {
        get throws {
            try identifier.wireFormat
                + host.wireFormat
                + DeclaredWidthData(body: symmetricKey.rawRepresentation).wireFormat
                + expiration.wireFormat
        }
    }
}

//we transform the date into a
extension Date: LinearEncodable {
    public static func parse(_ input: Data) throws -> (Date, Int) {
        let (hours, consumed) = try UInt32.parse(input)
        return (
            Date(timeIntervalSince1970: Double(hours) * 3600),
            consumed
        )
    }

    public var wireFormat: Data {
        UInt32((timeIntervalSince1970 / 3600).rounded())
            .wireFormat
    }

}

extension Resource: Equatable {}

//TODO: remove when removed from AgentHello
extension Resource: Codable {}
extension SymmetricKey: Codable {
    public init(from decoder: Decoder) throws {
        let value = try decoder.singleValueContainer()
        let symmetricKeyData = try value.decode(Data.self)
        self.init(data: symmetricKeyData)
    }

    public func encode(to encoder: Encoder) throws {
        var value = encoder.singleValueContainer()
        try value.encode(self.rawRepresentation)
    }
}
