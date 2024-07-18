//
//  KeyPackages.swift
//
//
//  Created by Mark @ Germ on 7/2/24.
//

import Foundation

public enum SessionEncryptionSuites: Codable, Equatable, Sendable, CaseIterable {
    case MLS_Curve25519_ChaChaPoly
    
    //match the RFC 9420 cipher suite
    var fixedWidth: Data {
        switch self {
        case .MLS_Curve25519_ChaChaPoly: Data([0x0, 0x03])
        }
    }
    
    init(fixedWidth: Data) throws {
        guard fixedWidth.count == 2,
              let first = fixedWidth.first,
              let second = fixedWidth.last else {
            throw ProtocolError.archiveIncorrect
        }
        switch(first, second) {
        case (0, 3): self = .MLS_Curve25519_ChaChaPoly
        default: throw ProtocolError.archiveIncorrect
        }
    }
}

public typealias KeyPackageChoices = [SessionEncryptionSuites: Data]
// for MLS, data value is an encoded MLS KeyPackage message

extension KeyPackageChoices: SignableObject {
    public static let type: SignableObjectTypes = .keyPackageChoices
}
