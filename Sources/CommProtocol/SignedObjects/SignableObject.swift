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
public protocol SignableObject {
    static var type: SignableObjectTypes { get }
}

///Encodes a wireformat of:
///[Byte indicating body type]
///[Byte indicating signature width][Signature bytes]
///[Body data]
public struct SignedObject<SignableObject>: Sendable {
    public let bodyType: SignableObjectTypes
    public let signature: TypedSignature
    public let body: Data //signature is over this particular encoding of SignableObject
    
    init(bodyType: SignableObjectTypes, signature: TypedSignature, body: Data) {
        self.bodyType = bodyType
        self.signature = signature
        self.body = body
    }
    
    public var wireFormat: Data {
        [bodyType.rawValue] + signature.wireFormat + body
    }
    
    //this parses the bodyType and typedSignature, leaving the caller to
    //use bodyType to determine how to parse the remainder
    static func parse(
        wireFormat: Data
    ) throws -> (SignableObjectTypes, TypedSignature, Data) {
        guard let first = wireFormat.first,
              let bodyType = SignableObjectTypes(rawValue: first),
              wireFormat.count > 1 else {
            throw DefinedWidthError.invalidTypedSignature
        }
        let (signature, body) = try TypedSignature
            .parse(wireFormat: Data( wireFormat[1...] ))
        guard let body else { throw DefinedWidthError.invalidTypedSignature }
        
        return (bodyType, signature, body)
    }
    
    func validate(
        for signer: any PublicSigningKey
    ) throws -> Data {
        guard signature.signingAlgorithm == type(of: signer).signingAlgorithm else {
            throw DefinedWidthError.invalidTypedKey
        }
        guard signer.isValidSignature(signature.signature, for: body) else {
            throw ProtocolError.authenticationError
        }
        return body
    }
}

extension SignedObject where SignableObject: Decodable {
    public func validate(
        for signer: any PublicSigningKey
    ) throws -> SignableObject {
        try validate(for: signer).decoded()
    }
}

extension SignedObject where SignableObject: WireFormat {
    public func validate(
        for signer: any PublicSigningKey
    ) throws -> SignableObject {
        try .init(wireFormat: validate(for: signer))
    }
}
