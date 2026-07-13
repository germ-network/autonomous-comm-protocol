//
//  IdentityMutableDataTests.swift
//  CommProtocol
//
//  Covers counter-based precedence used to reject replayed/rolled-back updates.
//

import Testing

@testable import CommProtocol

struct IdentityMutableDataTests {
	private func mutable(counter: UInt16) -> IdentityMutableData {
		.init(counter: counter, pronouns: [], aboutText: nil, imageResource: nil)
	}

	@Test func testSupersedes() {
		#expect(mutable(counter: 2).supersedes(mutable(counter: 1)))
		#expect(!mutable(counter: 1).supersedes(mutable(counter: 2)))
		#expect(!mutable(counter: 1).supersedes(mutable(counter: 1)))
	}

	@Test func testValidateSupersedesAcceptsNewerAndNoPrior() throws {
		try mutable(counter: 5).validateSupersedes(mutable(counter: 4))
		try mutable(counter: 5).validateSupersedes(nil)
	}

	@Test func testValidateSupersedesRejectsStaleAndEqual() {
		#expect(throws: ProtocolError.staleUpdate) {
			try mutable(counter: 3).validateSupersedes(mutable(counter: 4))
		}
		#expect(throws: ProtocolError.staleUpdate) {
			try mutable(counter: 4).validateSupersedes(mutable(counter: 4))
		}
	}
}
