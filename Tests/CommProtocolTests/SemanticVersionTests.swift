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
        let semVer = SemanticVersion.mock()

        let encoded = try semVer.wireFormat
        let decoded = try SemanticVersion.finalParse(encoded)

        #expect(semVer == decoded)
    }
}
