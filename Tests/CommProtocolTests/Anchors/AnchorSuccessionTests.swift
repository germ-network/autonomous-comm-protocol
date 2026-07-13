//
//  AnchorSuccessionTests.swift
//  CommProtocol
//
//  Regression coverage for anchor-key rotation continuity: after a rotation,
//  a Hello issued by the new anchor key carries a succession proof that a
//  recipient must be able to verify back to the predecessor key(s).
//

import AtprotoTypes
import AtprotoTypesMocks
import CommProtocol
import CryptoKit
import Testing

struct AnchorSuccessionTests {
	let did = Atproto.DID.mock()

	private func hello(
		from anchor: PrivateActiveAnchor
	) throws -> AnchorHello {
		try anchor.generateHello(
			helloAgent: anchor.createHelloAgent(),
			agentVersion: .mock(),
			mlsKeyPackages: ["mock".utf8Data],
			policy: .closed
		)
	}

	// Single rotation: the Hello from the rotated anchor must verify, and the
	// recovered succession chain must be exactly the predecessor key.
	// This is the direct regression guard for the verify(successionFrom:) direction.
	@Test func testHelloVerifiesAcrossOneRotation() throws {
		let v0 = PrivateActiveAnchor.create(for: did)
		let k0 = v0.publicKey

		let v1 = try v0.handOff()
		#expect(v1.publicKey != k0)

		let verified = try v1.publicKey.verify(
			hello: try hello(from: v1),
			for: .init(anchorTo: did)
		)
		#expect(verified.succession == [k0])
	}

	// Two rotations: continuity must reach all the way back to the original key,
	// in predecessor-first order. Exercises both the verify direction and that
	// handOff() accumulates (rather than truncates) proof history.
	@Test func testHelloVerifiesAcrossTwoRotations() throws {
		let v0 = PrivateActiveAnchor.create(for: did)
		let k0 = v0.publicKey
		let v1 = try v0.handOff()
		let k1 = v1.publicKey
		let v2 = try v1.handOff()

		let verified = try v2.publicKey.verify(
			hello: try hello(from: v2),
			for: .init(anchorTo: did)
		)
		#expect(verified.succession == [k0, k1])
	}

	// A freshly created anchor has no history; its Hello verifies with an empty
	// succession chain. This is the path the app exercises today and must stay green.
	@Test func testHelloWithoutRotationHasEmptySuccession() throws {
		let v0 = PrivateActiveAnchor.create(for: did)
		let verified = try v0.publicKey.verify(
			hello: try hello(from: v0),
			for: .init(anchorTo: did)
		)
		#expect(verified.succession.isEmpty)
	}
}
