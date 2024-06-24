//
//  TypedKeyMaterial.swift
//
//
//  Created by Mark Xue on 6/23/24.
//

import Foundation
import CryptoKit

public enum TypedKeyError: Error {
    case mismatchedAlgorithms(expected: TypedKeyMaterial.Algorithms,
                              found: TypedKeyMaterial.Algorithms)
    case unknownTypedKeyAlgorithm(UInt8)
    case invalidTypedKey
}

extension TypedKeyError: LocalizedError {
    public var errorDescription: String? {
        switch self{
        case .mismatchedAlgorithms(let expected, let found):
            "Mismatched key algorithm, expected \(expected), found \(found)"
        case .unknownTypedKeyAlgorithm(let index):
            "Unknown Typed Key Algorithm \(index)"
        case .invalidTypedKey: "Invalid typed key"
        }
    }
}

///Binary encoding of key data that prepends a bye enum of the algo type.
///Allows for cryptographic agility by denoting the algorithm in the first byte, which then determines the
///expected key width
///
///Avoids the overhead of base64 encoding if we store in codable structs
///
///The key's role and public/private is expected to be type-constrained in context,
///or could be specified with additional prefixes if differentiation is required in the wire/persisted format
public struct TypedKeyMaterial: Equatable, Sendable {
    public enum Algorithms: UInt8, Sendable { //using cryptokit naming conventions
        case ChaCha20Poly1305 //RFC 8439
        case Curve25519_KeyAgreement //RFC 8041
        case Curve25519_Signing //RFC 8410
        case HPKE_Encap_Curve25519_SHA256_ChachaPoly //RFC 9180
        
        var keyByteSize: UInt {
            switch self {
            case .ChaCha20Poly1305: 32
            case .Curve25519_KeyAgreement: 32
            case .Curve25519_Signing: 32
            case .HPKE_Encap_Curve25519_SHA256_ChachaPoly: 32 //Nenc
            }
        }
        
        var isSymmetric: Bool {
            switch self {
            case .ChaCha20Poly1305: true
            default: false
            }
        }
        
        var isEncapsulated: Bool {
            switch self {
            case .HPKE_Encap_Curve25519_SHA256_ChachaPoly: true
            default: false
            }
        }
        
        init(bytes: Data) throws(TypedKeyError) {
            guard let first = bytes.first else { throw .invalidTypedKey }
            guard let value = Self(rawValue: first) else {
                throw .unknownTypedKeyAlgorithm(first)
            }
            self = value
        }
    }
    
    public let algorithm: Algorithms
    public let keyData: Data
    
    public init(wireformat: Data) throws(TypedKeyError) {
        self.algorithm = try Algorithms(bytes: wireformat)
        guard wireformat.count == 1 + algorithm.keyByteSize else {
            throw .invalidTypedKey
        }
        keyData = .init(wireformat[1...])
        assert(keyData.count == algorithm.keyByteSize)
    }
    
    //Symmetric keys aren't typed, so we'll commonly specify the algo when creating
    public init(
        algorithm: Algorithms,
        symmetricKey: SymmetricKey
    ) throws(TypedKeyError) {
        guard algorithm.isSymmetric,
              algorithm.keyByteSize == symmetricKey.rawRepresentation.count else {
            throw .invalidTypedKey
        }
        self.algorithm = algorithm
        self.keyData = symmetricKey.rawRepresentation
    }
    
    //HPKE encapsulated key is just untyped Data
    public init(
        encapAlgorithm: Algorithms,
        data: Data
    ) throws(TypedKeyError) {
        guard encapAlgorithm.isEncapsulated,
              encapAlgorithm.keyByteSize == data.count else {
            throw .invalidTypedKey
        }
        self.algorithm = encapAlgorithm
        self.keyData = data
    }
    
    public init(
        typedKey: TypedKeyMaterialInput
    ) throws(TypedKeyError) {
        guard type(of: typedKey).encodeAlgorithm.keyByteSize == typedKey.rawRepresentation.count else {
            throw .invalidTypedKey
        }
        self.algorithm = type(of: typedKey).encodeAlgorithm
        self.keyData = typedKey.rawRepresentation
    }
    
    public var wireFormat: Data {
        [algorithm.rawValue] + keyData
    }
}

public protocol TypedKeyMaterialInput: RawRepresentableKey {
    static var encodeAlgorithm: TypedKeyMaterial.Algorithms { get }
}

extension TypedKeyMaterialInput {
    init(wireFormat: Data) throws {
        let typedWireFormat = try TypedKeyMaterial(wireformat: wireFormat)
        guard typedWireFormat.algorithm == Self.encodeAlgorithm else {
            throw TypedKeyError
                .mismatchedAlgorithms(expected: Self.encodeAlgorithm,
                                      found: typedWireFormat.algorithm)
        }
        try self.init(rawRepresentation: typedWireFormat.keyData)
    }
}

extension Curve25519.KeyAgreement.PublicKey: TypedKeyMaterialInput {
    static public let encodeAlgorithm: TypedKeyMaterial.Algorithms = .Curve25519_KeyAgreement
}

extension Curve25519.Signing.PublicKey: TypedKeyMaterialInput {
    static public let encodeAlgorithm: TypedKeyMaterial.Algorithms = .Curve25519_Signing
}
