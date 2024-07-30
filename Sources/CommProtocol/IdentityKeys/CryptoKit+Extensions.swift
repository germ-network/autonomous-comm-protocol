//
//  CryptoKit+Extensions.swift
//
//
//  Created by Mark Xue on 6/12/24.
//

import CryptoKit
///Protocol conformance for the bare CryptoKit key types
import Foundation

public protocol RawRepresentableKey {
    init<D>(rawRepresentation: D) throws where D: ContiguousBytes
    var rawRepresentation: Data { get }
}

//all of these are RawRepresentable, could combine extensions
extension Curve25519.KeyAgreement.PublicKey: RawRepresentableKey {}
extension Curve25519.Signing.PublicKey: RawRepresentableKey {}
