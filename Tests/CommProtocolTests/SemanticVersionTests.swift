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

        let reencoded: SemanticVersion =
            try semVer
            .encoded.decoded()

        #expect(semVer == reencoded)
    }
}
