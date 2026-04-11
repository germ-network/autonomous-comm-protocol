//
//  ATProtoDIDAPI.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 4/22/25.
//

import AtprotoTypes
import CommProtocol
import Testing

struct ATProtoDIDAPITests {
	@Test func testArchive() throws {
		let mock = Atproto.DID.mock()

		let restored = try Atproto.DID(string: mock.stringRepresentation)
		#expect(mock == restored)

		let attestation = DependentIdentity(anchorTo: restored)
		#expect(try attestation.wireFormat == attestation.archive.wireFormat)
	}
}
