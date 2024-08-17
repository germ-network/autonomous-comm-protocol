//
//  KeyPackages.swift
//
//
//  Created by Mark @ Germ on 7/2/24.
//

import Foundation

public enum SessionEncryptionSuites: UInt8, Equatable, Sendable, CaseIterable {
    case mlsCurve25519ChaChaPoly = 1

    //notice: unused
    //match the RFC 9420 cipher suite
    var fixedWidth: Data {
        switch self {
        case .mlsCurve25519ChaChaPoly: Data([0x0, 0x03])
        }
    }

    init(fixedWidth: Data) throws {
        guard fixedWidth.count == 2,
            let first = fixedWidth.first,
            let second = fixedWidth.last
        else {
            throw ProtocolError.archiveIncorrect
        }
        switch (first, second) {
        case (0, 3): self = .mlsCurve25519ChaChaPoly
        default: throw ProtocolError.archiveIncorrect
        }
    }
}

extension SessionEncryptionSuites: LinearEncodable {
    static public func parse(_ input: Data) throws(LinearEncodingError) -> (
        SessionEncryptionSuites,
        Int
    ) {
        guard let prefix = input.first,
            let suite = SessionEncryptionSuites(rawValue: prefix)
        else {
            throw LinearEncodingError.unexpectedData
        }
        return (suite, 1)
    }

    public var wireFormat: Data {
        .init([rawValue])
    }
}

// for MLS, data value is an encoded MLS KeyPackage message
public struct TypedKeyPackage: Equatable, Sendable {
    public let suite: SessionEncryptionSuites
    public let keyPackage: Data

    public init(suite: SessionEncryptionSuites, keyPackage: Data) {
        self.suite = suite
        self.keyPackage = keyPackage
    }
}

extension TypedKeyPackage: LinearEncodedPair {
    public var first: SessionEncryptionSuites { suite }
    public var second: Data { keyPackage }

    public init(first: SessionEncryptionSuites, second: Data) {
        self.init(suite: first, keyPackage: second)
    }
}

public typealias KeyPackageChoices = [TypedKeyPackage]
