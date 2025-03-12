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

        #expect(throws: LinearEncodingError.unexpectedEOF) {
            let _ = try UInt32.parse(.init())
        }

        #expect(throws: LinearEncodingError.incorrectDataLength) {
            let threeByte = Data([1, 1, 1])
            let _ = try UInt32(dataRepresentation: threeByte)
        }
        
        #expect(SemanticVersion(major: 1, minor: 1, patch: 1) < SemanticVersion(major: 1, minor: 1, patch: 2))

    }
}
