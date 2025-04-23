//
//  TestAnchor.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 4/22/25.
//

import Testing

@testable import CommProtocol

struct TestAnchorFull {

	@Test func testRestore() async throws {
		#expect(throws: ATProtoDIDError.invalidPrefix) {
			let _ = try ATProtoDID(fullId: "di:plc:example")
		}

		#expect(throws: ATProtoDIDError.invalidMethod) {
			let _ = try ATProtoDID(fullId: "did:method:example")
		}
	}

}
