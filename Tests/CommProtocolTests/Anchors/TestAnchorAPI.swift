//
//  Test.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 4/22/25.
//

import CommProtocol
import Testing

struct AnchorAPITests {
	@Test func testArchive() throws {
		let mock = ATProtoDID.mock()

		let restored = try ATProtoDID(fullId: mock.fullId)

		#expect(mock == restored)
	}
}
