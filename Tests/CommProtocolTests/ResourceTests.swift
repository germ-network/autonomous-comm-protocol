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

	@Test func testDateLinearEncoding() throws {
		let date = Date.now
		let encoded = date.wireFormat
		print("Encoded date width: \(encoded.count)")

		let decoded = try Date.finalParse(encoded)

		let difference = abs(decoded.timeIntervalSince(date))
		#expect(difference < 1)
	}

	@Test func testRoundedDateLinearEncoding() throws {
		let roundedDate = RoundedDate(date: .now)
		let encoded = roundedDate.wireFormat

		let decoded = try RoundedDate.finalParse(encoded)
		#expect(decoded == roundedDate)
	}
}
