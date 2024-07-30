//
//  KeyPackages.swift
//
//
//  Created by Mark @ Germ on 7/2/24.
//

import Foundation

public enum SessionEncryptionSuites: UInt8, Codable, Equatable, Sendable, CaseIterable {
    case mlsCurve25519ChaChaPoly = 1

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

public typealias KeyPackageChoices = [SessionEncryptionSuites: Data]
// for MLS, data value is an encoded MLS KeyPackage message
