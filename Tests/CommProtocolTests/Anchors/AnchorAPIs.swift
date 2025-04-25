//
//  AnchorAPIs.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 4/23/25.
//

import CommProtocol
import Testing

struct AnchorAPITests {
	let mockDID = ATProtoDID.mock()
	let privateAnchor: PrivateActiveAnchor

	init() throws {
		privateAnchor = try PrivateActiveAnchor.create(for: mockDID)
	}

	@Test func testAnchorValidate() throws {
		let (encrypted, publicAnchorKey, seed) =
			try privateAnchor.produceAnchor()

		let publicAnchor = try PublicAnchor.create(
			encrypted: encrypted,
			publicKey: publicAnchorKey,
			seed: seed
		)
		#expect(publicAnchor.publicKey == publicAnchorKey)
		let didAnchor = try #require(
			publicAnchor.verified.anchorTo as? ATProtoDID
		)
		#expect(didAnchor == mockDID)
		#expect(publicAnchor.verified.previousAnchor == nil)
	}

	@Test func testAnchorExchange() throws {
		let seed = DataIdentifier(width: .bits128)

		let (newAgent, encryptedHello) =
			try privateAnchor
			.createHello(
				agentVersion: .mock(),
				mlsKeyPackages: [.init()],
				seed: .init(data: seed.identifier)
			)
	}
}
