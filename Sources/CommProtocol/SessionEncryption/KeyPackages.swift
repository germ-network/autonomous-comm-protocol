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
public struct TypedKeyPackage: Equatable {
    let suite: SessionEncryptionSuites
    let keyPackage: Data
}

extension TypedKeyPackage: LinearEncodable {
    static public func parse(_ input: Data) throws -> (TypedKeyPackage, Int) {
        let (suite, declaredWidth, consumed) = try LinearEncoder.decode(
            SessionEncryptionSuites.self,
            DeclaredWidthData.self,
            input: input
        )

        let value = TypedKeyPackage(suite: suite, keyPackage: declaredWidth.body)
        return (value, consumed)
    }

    public var wireFormat: Data {
        get throws {
            try [suite.rawValue] + DeclaredWidthData(body: keyPackage).wireFormat
        }
    }
}

public typealias KeyPackageChoices = [TypedKeyPackage]
