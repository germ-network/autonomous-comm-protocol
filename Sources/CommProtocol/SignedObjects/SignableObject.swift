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

public struct SignedObject<SignableObject: Codable>: Codable, Sendable {
    public let bodyType: SignableObjectTypes
    public let signature: TypedSignature
    public let body: Data //siganture is over this particular encoding of SignableObject
    
    init(bodyType: SignableObjectTypes, signature: TypedSignature, body: Data) {
        self.bodyType = bodyType
        self.signature = signature
        self.body = body
    }
    
    var wireFormat: Data {
        [bodyType.rawValue] + signature.wireFormat + body
    }
    
    init(wireFormat: Data) throws(TypedKeyError) {
        guard let first = wireFormat.first,
              let bodyType = SignableObjectTypes(rawValue: first),
              wireFormat.count > 1 else {
            throw .invalidTypedSignature
        }
        let (signature, body) = try TypedSignature
            .readPrefix(data: Data( wireFormat[1...] ))
        guard let body else { throw .invalidTypedSignature }
        self.bodyType = bodyType
        self.signature = signature
        self.body = body
    }
    
    //MARK: Codable
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(wireFormat)
    }
    
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let wireFormat: Data = try container.decode(Data.self)
        try self.init(wireFormat: wireFormat)
    }
    
    public func validate(
        for signer: Curve25519.Signing.PublicKey
    )throws -> SignableObject {
        guard signature.signingAlgorithm == .curve25519 else {
            throw TypedKeyError.invalidTypedKey
        }
        
        guard signer.isValidSignature(signature.signature,
                                      for: body) else {
            throw ProtocolError.authenticationError
        }
        return try body.decoded()
    }
}
