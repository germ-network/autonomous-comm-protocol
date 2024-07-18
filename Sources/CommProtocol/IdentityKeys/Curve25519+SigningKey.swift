//
//  Curve25519+Extensions.swift
//
//
//  Created by Mark @ Germ on 6/15/24.
//

import Foundation
import CryptoKit

extension Curve25519.Signing.PrivateKey: @retroactive @unchecked Sendable {}
extension Curve25519.Signing.PrivateKey: PrivateSigningKey {
    public static let encodeAlgorithm: TypedKeyMaterial.Algorithms = .Curve25519_Signing
    
    static let signingAlgorithm: SigningKeyAlgorithm = .curve25519
}

extension Curve25519.Signing.PublicKey: @retroactive @unchecked Sendable {}
extension Curve25519.Signing.PublicKey: PublicSigningKey {
    public static let signingAlgorithm: SigningKeyAlgorithm = .curve25519
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
