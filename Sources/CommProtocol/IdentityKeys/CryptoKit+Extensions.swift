//
//  CryptoKit+Extensions.swift
//
//
//  Created by Mark Xue on 6/12/24.
//

///Protocol conformance for the bare CryptoKit key types
import Foundation
import CryptoKit

public protocol RawRepresentableKey {
    init<D>(rawRepresentation: D) throws where D : ContiguousBytes
    var rawRepresentation: Data { get }
}

//all of these are RawRepresentable, could combine extensions
extension Curve25519.KeyAgreement.PrivateKey: RawRepresentableKey, Codable {
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



extension Curve25519.KeyAgreement.PublicKey: RawRepresentableKey, Codable {
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

extension Curve25519.Signing.PublicKey: RawRepresentableKey, Codable {
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


