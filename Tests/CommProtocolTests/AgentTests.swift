//
//  AgentTests.swift
//
//
//  Created by Mark Xue on 6/13/24.
//

import CryptoKit
import Foundation
import Testing

@testable import CommProtocol

struct AgentKeyTests {
	let privateKey = AgentPrivateKey(algorithm: .curve25519)

	@Test func testCoding() throws {
		let rehydrated: AgentPrivateKey = try .init(archive: privateKey.archive)
		#expect(privateKey.archive == rehydrated.archive)

		let publicKey = privateKey.publicKey
		let rehydratedPublic: AgentPublicKey = try .init(archive: publicKey.id)
		#expect(publicKey.id == rehydratedPublic.id)
	}

	@Test func testWireFormat() throws {
		let publicWireFormat = privateKey.publicKey.wireFormat

		let decodedPublic = try AgentPublicKey(wireFormat: publicWireFormat)
		#expect(privateKey.publicKey == decodedPublic)

		let symmetricKey = try TypedKeyMaterial(
			algorithm: .chaCha20Poly1305,
			symmetricKey: SymmetricKey(size: .bits256)
		)

		#expect(throws: ProtocolError.typedKeyArchiveMismatch) {
			let _ = try AgentPrivateKey(archive: symmetricKey)
		}

		#expect(throws: ProtocolError.typedKeyArchiveMismatch) {
			let _ = try AgentPublicKey(archive: symmetricKey)
		}
	}

	@Test func testHash() throws {
		let firstKey = privateKey.publicKey
		let secondKey = AgentPrivateKey(algorithm: .curve25519).publicKey

		#expect(firstKey.hashValue == firstKey.hashValue)
		#expect(firstKey.hashValue != secondKey.hashValue)
	}
}
