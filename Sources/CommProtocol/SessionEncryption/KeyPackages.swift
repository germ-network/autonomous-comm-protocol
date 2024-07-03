//
//  KeyPackages.swift
//
//
//  Created by Mark @ Germ on 7/2/24.
//

import Foundation

public enum SessionEncryptionSuites: UInt8, Codable, Sendable {
    case MLS_Curve25519_ChaChaPoly
}

public struct KeyPackageChoices: Codable, Sendable {
    let selection: [SessionEncryptionSuites: Data]
    // for MLS, is an encoded MLS KeyPackage message
}

extension KeyPackageChoices: SignableObject {
    public static var type: SignableObjectTypes = .keyPackageChoices    
}
