//
//  SemanticVersion.swift
//
//
//  Created by Mark @ Germ on 8/4/23.
//

import Foundation

public enum SemanticField: Equatable, Hashable, Codable, Sendable {
    case alpha(String)
    case numeric(UInt)
    
    var string: String {
        switch self{
        case .alpha(let string):
            string
        case .numeric(let uint):
                .init(uint)
        }
    }
}

public struct SemanticVersion: Equatable, Hashable, Codable, Sendable {
    let major: SemanticField
    let minor: SemanticField
    let patch: SemanticField
 
    public init(major: UInt, minor: UInt, patch: UInt) {
        self.major = .numeric(major)
        self.minor = .numeric(minor)
        self.patch = .numeric(patch)
    }
    
    public init(major: SemanticField, minor: SemanticField, patch: SemanticField) {
        self.major = major
        self.minor = minor
        self.patch = patch
    }
    
    public var string: String {
        [major.string, minor.string, patch.string].joined(separator: ".")
    }
}
