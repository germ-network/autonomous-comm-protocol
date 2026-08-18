//
//  MailboxGrantTests.swift
//  CommProtocol
//

import Crypto
import Foundation
import Testing

@testable import CommProtocol

private func rangeBytes(_ range: Range<UInt8>) -> Data {
	Data(range)
}

struct MailboxGrantTests {

	private static let zeroKey = try! TypedKeyMaterial(
		algorithm: .hmacSha256,
		symmetricKey: SymmetricKey(data: Data(count: 32))
	)

	// MARK: - KATs, cross-validated against germ-service's test/mailbox-hmac.spec.ts

	@Test func testAddressKnownAnswer() throws {
		let grant = try MailboxGrant(
			authKey: Self.zeroKey, serviceHost: "ger.mx", expiration: .now)
		// Independently computed: hmac.new(bytes(32), b"germ-addr:v1" + b"ger.mx",
		// sha256).hexdigest() == 193221da6fb96fb001ff056007a9e84792acd4b34ab8af79905e7d86d8976435
		// — the exact vector in germ-service's test/mailbox-hmac.spec.ts. This
		// asserts the base64url string form, since that's what actually rides
		// the wire (and what `putTag` below is keyed against).
		#expect(grant.address == "GTIh2m-5b7AB_wVgB6noR5Ks1LNKuK95kF59htiXZDU")
	}

	@Test func testPutTagKnownAnswer() throws {
		let grant = try MailboxGrant(
			authKey: Self.zeroKey, serviceHost: "ger.mx", expiration: .now)
		let nonce = rangeBytes(0..<32)
		let bodyDigest = rangeBytes(32..<64)
		let tag = grant.putTag(nonce: nonce, bodyDigest: bodyDigest)
		// germ-service's own putTag KAT exercises the raw HMAC in isolation
		// against a placeholder address string ("some-address-string"), which
		// this API can't reproduce directly — a grant always signs under its
		// own derived address. So this vector instead chains off the address
		// KAT above (independently computed the same way: hmac.new(bytes(32),
		// b"germ-put:v1" + address.encode() + nonce + bodyDigest,
		// sha256).hexdigest()), exercising the real coupled API rather than
		// the server's decoupled one.
		#expect(
			tag
				== Data(
					hexString:
						"67ec98aad3d2bf4551195c3a23db92c4a2f79cda35732c3eca9ac67eda19b1b6"
				)
		)
	}

	@Test func testAddressDiffersByServiceHost() throws {
		let a = try MailboxGrant(
			authKey: Self.zeroKey, serviceHost: "ger.mx", expiration: .now)
		let b = try MailboxGrant(
			authKey: Self.zeroKey, serviceHost: "other.example", expiration: .now)
		#expect(a.address != b.address)
	}

	@Test func testPutTagDiffersByNonce() throws {
		let grant = try MailboxGrant(
			authKey: Self.zeroKey, serviceHost: "ger.mx", expiration: .now)
		let digest = rangeBytes(32..<64)
		let a = grant.putTag(nonce: rangeBytes(0..<32), bodyDigest: digest)
		let b = grant.putTag(nonce: rangeBytes(1..<33), bodyDigest: digest)
		#expect(a != b)
	}

	@Test func testRejectsAKeyThatIsNot32Bytes() {
		#expect(throws: (any Error).self) {
			try TypedKeyMaterial(
				algorithm: .hmacSha256,
				symmetricKey: SymmetricKey(data: Data(count: 16)))
		}
	}

	@Test func testRejectsAnAuthKeyOfTheWrongAlgorithm() {
		let wrongAlgorithm = try! TypedKeyMaterial(
			algorithm: .chaCha20Poly1305,
			symmetricKey: SymmetricKey(size: .bits256)
		)
		#expect(throws: (any Error).self) {
			try MailboxGrant(
				authKey: wrongAlgorithm, serviceHost: "ger.mx", expiration: .now)
		}
	}

	// MARK: - Equatable (excludes expiration)

	@Test func testEqualityIgnoresExpiration() throws {
		let a = try MailboxGrant(
			authKey: Self.zeroKey, serviceHost: "ger.mx", expiration: Date())
		let b = try MailboxGrant(
			authKey: Self.zeroKey,
			serviceHost: "ger.mx",
			expiration: Date().addingTimeInterval(3600)
		)
		#expect(a == b)
	}

	@Test func testInequalityByAuthKey() throws {
		let otherKey = try TypedKeyMaterial(
			algorithm: .hmacSha256,
			symmetricKey: SymmetricKey(data: Data(repeating: 1, count: 32))
		)
		let a = try MailboxGrant(
			authKey: Self.zeroKey, serviceHost: "ger.mx", expiration: .now)
		let b = try MailboxGrant(authKey: otherKey, serviceHost: "ger.mx", expiration: .now)
		#expect(a != b)
	}

	// MARK: - CBOR round-trip

	@Test func testCborRoundTrip() throws {
		let original = try MailboxGrant(
			authKey: Self.zeroKey,
			serviceHost: "ger.mx",
			expiration: Date()
		)
		let encoded = try original.wireFormat
		let decoded = try MailboxGrant(wireFormat: encoded)
		#expect(decoded == original)
		#expect(decoded.expiration == original.expiration)  // Equatable ignores this — check directly
	}

	// MARK: - Wire-pinning

	@Test func testCborWireFormatGolden() throws {
		let key = try TypedKeyMaterial(
			algorithm: .hmacSha256,
			symmetricKey: SymmetricKey(data: Data(count: 32))
		)
		let grant = try MailboxGrant(
			authKey: key,
			serviceHost: "ger.mx",
			expiration: RoundedDate(hoursSinceEpoch: 471442)
		)
		let encoded = try grant.wireFormat
		// Locks the encoding against drift: a renamed CodingKeys raw value or
		// a reordered field must fail HERE, in CI. Byte-verified by hand at
		// introduction: a3 (map, 3 pairs) / 61 65 (key "e") 1a 00073192
		// (uint32 471442) / 61 68 (key "h") 66 <"ger.mx"> (text, 6 bytes) /
		// 61 6b (key "k") 58 21 <05 + 32 zero bytes> (byte string, 33 bytes:
		// the .hmacSha256 algorithm tag + a 32-byte all-zero key) — RFC 8949
		// bytewise key order ("e" < "h" < "k").
		#expect(
			encoded
				== Data(
					hexString:
						"a361651a000731926168666765722e6d78616b5821050000000000000000000000000000000000000000000000000000000000000000"
				)
		)
	}

	// MARK: - ProtocolAddress bridge

	@Test func testProtocolAddressBridgeRoundTrip() throws {
		let grant = try MailboxGrant(
			authKey: Self.zeroKey, serviceHost: "ger.mx", expiration: Date())
		let address = ProtocolAddress(mailboxGrant: grant)
		#expect(address.serviceHost == grant.serviceHost)
		#expect(address.mailboxGrant == grant)
		#expect(address.mailboxGrant?.expiration == grant.expiration)
	}

	@Test func testProtocolAddressBridgeDiscriminatesLegacyUUID() {
		// Legacy addresses are `crypto.randomUUID()` — 36 characters, which
		// decode as base64url to 27 bytes, never 32. Never a grant.
		let legacy = ProtocolAddress(
			identifier: UUID().uuidString,
			serviceHost: "ger.mx",
			expiration: Date()
		)
		#expect(legacy.mailboxGrant == nil)
	}

	@Test func testProtocolAddressBridgeRejectsGarbageIdentifier() {
		let garbage = ProtocolAddress(
			identifier: "not-base64url-shaped-at-all!!",
			serviceHost: "ger.mx",
			expiration: Date()
		)
		#expect(garbage.mailboxGrant == nil)
	}
}
