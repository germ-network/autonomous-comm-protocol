//
//  ResourceTests.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 7/31/24.
//

import Foundation
import Testing

@testable import CommProtocol

struct ResourceTests {

    @Test func testDateLinearEncoding() async throws {
        // Write your test here and use APIs like `#expect(...)` to check expected conditions.
        let date = Date(timeIntervalSinceNow: 3600 * 24 * 14)
        let encoded = date.wireFormat
        print("Encoded date width: \(encoded.count))")

        let decoded = try Date.finalParse(encoded)

        let difference = abs(decoded.timeIntervalSince(date))
        #expect(difference < 3600)
    }

}
