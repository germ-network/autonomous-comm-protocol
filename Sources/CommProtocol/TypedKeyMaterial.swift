//
//  TypedKeyMaterial.swift
//
//
//  Created by Mark Xue on 6/23/24.
//

import Foundation
import CryptoKit

///Binary encoding of key data that prepends a byte enum of the algo type.
///Allows for cryptographic agility by denoting the algorithm in the first byte, which then determines the
///expected key width
///
///Avoids the overhead of base64 encoding if we store in codable structs
///
///The key's role and public/private is expected to be type-constrained in context,
///or could be specified with additional prefixes if differentiation is required in the wire/persisted format
public struct TypedKeyMaterial: DefinedWidthBinary, Equatable, Hashable, Sendable  {
    public typealias Prefix = Algorithms
    public enum Algorithms: UInt8, DefinedWidthPrefix, Sendable { //using cryptokit naming conventions
        case AES_GCM_256 //RFC 7714 (used for webCrypto compatibility )
        case ChaCha20Poly1305 //RFC 8439
        case Curve25519_KeyAgreement //RFC 7748
        case Curve25519_Signing //RFC 8032
        case HPKE_Encap_Curve25519_SHA256_ChachaPoly //RFC 9180
        
        public var contentByteSize: Int { keyByteSize }
        
        private var keyByteSize: Int {
            switch self {
            case .AES_GCM_256: 32
            case .ChaCha20Poly1305: 32
            case .Curve25519_KeyAgreement: 32
            case .Curve25519_Signing: 32
            case .HPKE_Encap_Curve25519_SHA256_ChachaPoly: 32 //Nenc
            }
        }
        
        var isSymmetric: Bool {
            switch self {
            case .ChaCha20Poly1305, .AES_GCM_256: true
            default: false
            }
        }
        
        var isEncapsulated: Bool {
            switch self {
            case .HPKE_Encap_Curve25519_SHA256_ChachaPoly: true
            default: false
            }
        }
    }
    
    public let algorithm: Algorithms
    public let keyData: Data
    
    public var wireFormat: Data {
        [algorithm.rawValue] + keyData
    }
    
    public init(prefix: Prefix, checkedData: Data) throws(LinearEncodingError) {
        guard prefix.contentByteSize == checkedData.count else {
            throw .incorrectDataLength
        }
        self.algorithm = prefix
        self.keyData = checkedData
    }
    
    //Symmetric keys aren't typed, so we'll commonly specify the algo when creating
    public init(
        algorithm: Algorithms,
        symmetricKey: SymmetricKey
    ) throws(LinearEncodingError) {
        guard algorithm.isSymmetric,
              algorithm.contentByteSize == symmetricKey.rawRepresentation.count else {
            throw .invalidTypedKey
        }
        self.algorithm = algorithm
        self.keyData = symmetricKey.rawRepresentation
    }
    
    //HPKE encapsulated key is just untyped Data
    public init(
        encapAlgorithm: Algorithms,
        data: Data
    ) throws(LinearEncodingError) {
        guard encapAlgorithm.isEncapsulated,
              encapAlgorithm.contentByteSize == data.count else {
            throw .invalidTypedKey
        }
        self.algorithm = encapAlgorithm
        self.keyData = data
    }
    
    public init(
        typedKey: TypedKeyMaterialInput
    ) {
        //expecting implementation of .rawRepresentation to produce the correct outptu
        assert(type(of: typedKey).encodeAlgorithm.contentByteSize == typedKey.rawRepresentation.count)
        self.algorithm = type(of: typedKey).encodeAlgorithm
        self.keyData = typedKey.rawRepresentation
    }
}

public protocol TypedKeyMaterialInput: RawRepresentableKey {
    static var encodeAlgorithm: TypedKeyMaterial.Algorithms { get }
}

extension TypedKeyMaterialInput {
    init(wireFormat: Data) throws {
        let typedWireFormat = try TypedKeyMaterial(wireFormat: wireFormat)
        guard typedWireFormat.algorithm == Self.encodeAlgorithm else {
            throw LinearEncodingError
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
