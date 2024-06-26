//
//  Curve25519+Extensions.swift
//
//
//  Created by Mark @ Germ on 6/15/24.
//

import Foundation
import CryptoKit

extension Curve25519.Signing.PrivateKey: @unchecked @retroactive Sendable {}
extension Curve25519.Signing.PrivateKey: TypedKeyMaterialInput {}
extension Curve25519.Signing.PrivateKey: PrivateSigningKey {
    static var signingAlgorithm: SigningKeyAlgorithm = .curve25519
    static public var encodeAlgorithm: TypedKeyMaterial.Algorithms = .Curve25519_Signing
    static func newKeyPair() -> (Self, PublicKey) {
        let newKey = Curve25519.Signing.PrivateKey()
        return (newKey, newKey.publicKey)
    }
}

extension Curve25519.Signing.PrivateKey: RawRepresentableKey, Codable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let data = try container.decode(Data.self)
        try self.init(rawRepresentation: data)
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawRepresentation)
    }
}

extension Curve25519.Signing.PublicKey: @unchecked @retroactive Sendable {}
extension Curve25519.Signing.PublicKey: PublicSigningKey {
    public static var signingAlgorithm: SigningKeyAlgorithm = .curve25519
}

extension Curve25519.Signing.PublicKey: @retroactive Equatable {
    public static func == (lhs: Curve25519.Signing.PublicKey, rhs: Curve25519.Signing.PublicKey) -> Bool {
        return lhs.rawRepresentation == rhs.rawRepresentation
    }
}
extension Curve25519.Signing.PublicKey: @retroactive Hashable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(rawRepresentation)
    }
}
