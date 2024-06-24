//
//  SemanticVersionTests.swift
//
//
//  Created by Mark @ Germ on 6/24/24.
//

import Foundation
import Testing
@testable import CommProtocol
struct Test {

    @Test func testSemVerCoding() throws {
        let semVer = SemanticVersion(major: .random,
                                     minor: .random,
                                     patch: .random)
        
        let reencoded: SemanticVersion = try semVer
            .encoded.decoded()
        
        #expect(semVer == reencoded)
    }
}

extension SemanticField {
    static var random: SemanticField {
        get {
            if Bool.random() {
                .alpha(UUID().uuidString)
            } else {
                .numeric(UInt.random(in: UInt.min...UInt.max))
            }
        }
    }
}
