//
//  EncodingTests.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 7/31/24.
//

import Foundation
import Testing

@testable import CommProtocol

struct EncodingTests {

    @Test func testSemVer() throws {
        // Write your test here and use APIs like `#expect(...)` to check expected conditions.
        let semVer = SemanticVersion.mock()
        let encodedSemVer = try semVer.wireFormat
        let decodedSemVer = try SemanticVersion.finalParse(encodedSemVer)

        #expect(semVer == decodedSemVer)
    }

    @Test func testOptString() throws {
        let nilString: String? = nil
        let encodedNil = try OptionalString(nilString).wireFormat
        let decodedNil = try OptionalString.finalParse(encodedNil)
        #expect(decodedNil.string == nil)

        let string = UUID().uuidString
        let encoded = try OptionalString(string).wireFormat
        let decoded = try OptionalString.finalParse(encoded)
        #expect(decoded.string == string)
    }

}
