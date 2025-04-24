//
//  AnchorAPIs.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 4/23/25.
//

import CommProtocol
import Testing

struct AnchorAPITests {

	@Test func testAnchorLifeCycle() throws {
		let mockDID = ATProtoDID.mock()
		let privateAnchor = try PrivateActiveAnchor.create(for: mockDID)

	}

}
