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

	@Test func testRoundedDateLinearEncoding() throws {
		let roundedDate = RoundedDate(date: .now)
		let encoded = roundedDate.wireFormat

		let decoded = try RoundedDate.finalParse(encoded)
		#expect(decoded == roundedDate)
	}
}
