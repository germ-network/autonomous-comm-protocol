//
//  SignableObject.swift
//
//
//  Created by Mark @ Germ on 6/16/24.
//

import Foundation
import CryptoKit

public enum SignableObjectTypes: UInt8, Codable, Sendable {
    case identityDigest
    case identityMutableData
    case encryptedResource
}

//ensure signed objects state their type
public protocol SignableObject: Codable {
    static var type: SignableObjectTypes { get }
}

public struct SignedObject<SignableObject: Decodable>: Sendable, Codable, Hashable {
    public let body: Data
    public let signature: Data
    
//    public func validate(
//        for signer: Curve25519.Signing.PublicKey
//    )throws -> SignableObject {
//        guard signer.isValidSignature(signature, for: body) else {
//            throw ProtocolError.authenticationError
//        }
//        return try body.decoded()
//    }
}
