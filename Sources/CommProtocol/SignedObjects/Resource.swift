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
    
    public let identifier: String //base64 decodes to digest of the ciphertext
    public let host: String
    public let symmetricKey: SymmetricKey
    public var expiration: Date //temporarily var to allow for migration
    //TODO: handle expiration
//    [IOS-115 handle expiration of the resource object](https://germnetwork.atlassian.net/browse/IOS-115)
}

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
