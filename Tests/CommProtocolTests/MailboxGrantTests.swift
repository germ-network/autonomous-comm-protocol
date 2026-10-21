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
		// Equatable ignores this — check directly
		#expect(decoded.expiration == original.expiration)
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

	/// The bridge has no room for a version, so whatever rides it is legacy.
	@Test func testBridgeYieldsLegacyGrant() throws {
		let grant = try MailboxGrant(
			authKey: Self.zeroKey, serviceHost: "ger.mx", expiration: Date(),
			version: .germPMR)
		#expect(ProtocolAddress(mailboxGrant: grant).mailboxGrant?.version == .legacy)
	}

	// MARK: - Version key

	private static func grant(_ version: MailboxGrant.Version) throws -> MailboxGrant {
		try MailboxGrant(
			authKey: zeroKey,
			serviceHost: "ger.mx",
			expiration: RoundedDate(hoursSinceEpoch: 471442),
			version: version
		)
	}

	/// A hand-built carriage, so a decoder can be fed a `v` no encoder here
	/// would write.
	private struct RawArchive: Codable {
		let k: Data
		let h: String
		let e: UInt32
		let v: UInt64?
	}

	private static func rawGrant(v: UInt64?) throws -> Data {
		try DeterministicCbor.encode(
			RawArchive(k: zeroKey.wireFormat, h: "ger.mx", e: 471442, v: v)
		)
	}

	/// A legacy grant's bytes are those every release before the `"v"` key
	/// wrote, so peers on 1.13.1 and earlier read it unchanged.
	@Test func testLegacyGrantOmitsVersionKey() throws {
		#expect(try Self.grant(.legacy).wireFormat == Self.rawGrant(v: nil))
		#expect(try MailboxGrant(wireFormat: Self.rawGrant(v: nil)).version == .legacy)
	}

	@Test func testGermPMRCborWireFormatGolden() throws {
		// The legacy golden's map grown to four pairs (a4), with `61 76 02`
		// ("v": 2) last in RFC 8949 bytewise key order ("e" < "h" < "k" < "v").
		#expect(
			try Self.grant(.germPMR).wireFormat
				== Data(
					hexString:
						"a461651a000731926168666765722e6d78616b5821050000000000000000000000000000000000000000000000000000000000000000617602"
				)
		)
	}

	@Test func testGermPMRCborRoundTrip() throws {
		let original = try Self.grant(.germPMR)
		let decoded = try MailboxGrant(wireFormat: original.wireFormat)
		#expect(decoded == original)
		#expect(decoded.version == .germPMR)
	}

	@Test func testDecodeRejectsUnknownVersion() throws {
		let unknown = try Self.rawGrant(v: 3)
		#expect(throws: (any Error).self) {
			try MailboxGrant(wireFormat: unknown)
		}
	}

	/// "Absent means 1": an explicit 1 reads as legacy, and re-encodes
	/// without the key.
	@Test func testDecodeAcceptsExplicitLegacyVersion() throws {
		let decoded = try MailboxGrant(wireFormat: Self.rawGrant(v: 1))
		#expect(decoded.version == .legacy)
		#expect(try decoded.wireFormat == Self.rawGrant(v: nil))
	}

	@Test func testInequalityByVersion() throws {
		#expect(try Self.grant(.legacy) != Self.grant(.germPMR))
	}

	// MARK: - Germ PMR KATs, from the Germ PMR spec's reference vectors

	@Test func testGermPMRAddressKnownAnswer() throws {
		// hmac.new(bytes(32), b"germ-pmr:grant-addr:v1" + b"ger.mx",
		// sha256) == 957a006045548cb182426117a79e6c633727878e8151ee7e7938026fb2cacf6f
		#expect(
			try Self.grant(.germPMR).address
				== "lXoAYEVUjLGCQmEXp55sYzcnh46BUe5-eTgCb7LKz28")
	}

	@Test func testGermPMRAddressKnownAnswerOtherHost() throws {
		let grant = try MailboxGrant(
			authKey: Self.zeroKey, serviceHost: "other.example", expiration: .now,
			version: .germPMR)
		// The spec's vector, 8f3ec8cacb66ad9e…, as base64url.
		#expect(grant.address == "jz7IystmrZ66fqKVVKVH0NgnG0TtCv8otY2K51nU6rg")
	}

	@Test func testGermPMRAddressKnownAnswerOtherKey() throws {
		let key = try TypedKeyMaterial(
			algorithm: .hmacSha256,
			symmetricKey: SymmetricKey(data: Data(repeating: 1, count: 32))
		)
		let grant = try MailboxGrant(
			authKey: key, serviceHost: "ger.mx", expiration: .now, version: .germPMR)
		// The spec's vector, 5fabab601a24b20b…, as base64url.
		#expect(grant.address == "X6urYBoksgvnajSyND4KX8MF5CtAooP7_BN4yKJ0VO8")
	}

	@Test func testGermPMRPutTagKnownAnswer() throws {
		// hmac.new(bytes(32), b"germ-pmr:grant-put:v1" + address.encode()
		// + bytes(range(32)) + bytes(range(32, 64)), sha256)
		let tag = try Self.grant(.germPMR).putTag(
			nonce: rangeBytes(0..<32), bodyDigest: rangeBytes(32..<64))
		#expect(
			tag
				== Data(
					hexString:
						"21691c49aeb4dd1cde5600ae404e554874f1c5383b6a7d7f4b3ec52aea914933"
				)
		)
	}

	/// The host PMR grants are actually issued on — computed independently
	/// the same way as the spec's vectors, which use `ger.mx`.
	@Test func testGermPMRAddressAtPMRHostKnownAnswer() throws {
		let grant = try MailboxGrant(
			authKey: Self.zeroKey, serviceHost: "pmr.ger.mx", expiration: .now,
			version: .germPMR)
		#expect(grant.address == "xcbrhhcR-vkag3lDpsth0YgPrt-0A08WymlqCUUMrPM")
		#expect(
			grant.putTag(nonce: rangeBytes(0..<32), bodyDigest: rangeBytes(32..<64))
				== Data(
					hexString:
						"404cbc981243a2a5117d8989d56998ade7a9f0aaf9f4bedd6ce598390c833ce3"
				)
		)
	}

	/// The same key under the two schemes must never validate against both.
	@Test func testSchemesDeriveDifferentAddresses() throws {
		let legacy = try Self.grant(.legacy)
		let pmr = try Self.grant(.germPMR)
		#expect(legacy.address != pmr.address)
		let nonce = rangeBytes(0..<32)
		let digest = rangeBytes(32..<64)
		#expect(
			legacy.putTag(nonce: nonce, bodyDigest: digest)
				!= pmr.putTag(nonce: nonce, bodyDigest: digest))
	}
}
