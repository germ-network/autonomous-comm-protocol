//
//  Resource.swift
//
//
//  Created by Mark @ Germ on 6/18/24.
//

import Foundation
@preconcurrency import CryptoKit
//local representation of the resource
//signed to prevent wire injection of a malicious URI
public struct Resource: SignableObject, Sendable, Codable {
    public static let type: SignableObjectTypes = .encryptedResource
    public var type: SignableObjectTypes = .encryptedResource
    
    public struct Constants {
        public static let minExpiration = TimeInterval(24 * 3600)
    }
    
    public let identifier: String //base64url decodes to digest of the ciphertext
    public let plaintextDigest: Data
    public let host: String
    public let symmetricKey: SymmetricKey
    public let expiration: Date 
    
    public init(identifier: String, plaintextDigest: Data, host: String, symmetricKey: SymmetricKey, expiration: Date) {
        self.identifier = identifier
        self.plaintextDigest = plaintextDigest
        self.host = host
        self.symmetricKey = symmetricKey
        self.expiration = expiration
    }
}

extension Resource: Equatable {}

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


