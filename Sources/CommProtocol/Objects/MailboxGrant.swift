//
//  MailboxGrant.swift
//  CommProtocol
//

import Base64
import Crypto
import Foundation

/// An authenticated mailbox address, minted by a server and shared with a
/// peer so it can message the holder — the successor to `ProtocolAddress` in
/// new carriage (docs/attachment-mailbox-delivery.md, "Authenticated
/// addresses").
///
/// Deliberately has **no identifier field**: unlike a legacy address (a bare
/// bearer token), both the address and the put-authentication tag are HMAC
/// derivations of `authKey`, so a peer holding the grant derives them itself
/// rather than trusting a transmitted value. `address` and `putTag(nonce:
/// bodyDigest:)`, below, are that derivation — matching germ-service's
/// `deriveMailboxAddress`/`computePutTag` (`authentication/mailbox-hmac.ts`)
/// byte-for-byte, so KATs are shared between the two implementations.
public struct MailboxGrant: Sendable {
	public let authKey: TypedKeyMaterial  // .hmacSha256, 32B
	public let serviceHost: String
	public let expiration: RoundedDate

	public init(
		authKey: TypedKeyMaterial,
		serviceHost: String,
		expiration: Date
	) throws(LinearEncodingError) {
		try self.init(
			authKey: authKey,
			serviceHost: serviceHost,
			expiration: RoundedDate(date: expiration)
		)
	}

	init(
		authKey: TypedKeyMaterial,
		serviceHost: String,
		expiration: RoundedDate
	) throws(LinearEncodingError) {
		guard authKey.algorithm == .hmacSha256 else {
			throw .mismatchedAlgorithms(expected: .hmacSha256, found: authKey.algorithm)
		}
		self.authKey = authKey
		self.serviceHost = serviceHost
		self.expiration = expiration
	}
}

// A grant is identified by its key and host, not its expiration — matching
// `ProtocolAddress`'s precedent (the type it succeeds).
extension MailboxGrant: Equatable {
	public static func == (lhs: MailboxGrant, rhs: MailboxGrant) -> Bool {
		lhs.authKey == rhs.authKey && lhs.serviceHost == rhs.serviceHost
	}
}

// MARK: - Derivation

extension MailboxGrant {
	private static let addressLabel = Data("germ-addr:v1".utf8)
	private static let putLabel = Data("germ-put:v1".utf8)

	/// The address a sender messages to reach this grant's holder — derived,
	/// never transmitted. `base64url(HMAC-SHA256(authKey, "germ-addr:v1" ‖
	/// serviceHost))`, unpadded.
	public var address: String {
		let key = SymmetricKey(data: authKey.keyData)
		let message = Self.addressLabel + Data(serviceHost.utf8)
		let mac = HMAC<SHA256>.authenticationCode(for: message, using: key)
		return Data(mac).base64URLEncoded(padded: false)
	}

	/// The tag a put's `Authorization` header carries, authenticating a body
	/// whose digest is `bodyDigest` against this grant's `nonce`-bound
	/// challenge. `HMAC-SHA256(authKey, "germ-put:v1" ‖ address ‖ nonce ‖
	/// bodyDigest)`.
	///
	/// Byte representations are fixed, matching the server's contract
	/// (`mailbox-hmac.ts`'s header comment): `address` is the UTF-8 bytes of
	/// its base64url *string* form (43 bytes), `nonce` is the raw bytes
	/// returned by the put-challenge (not re-encoded), and `bodyDigest` is
	/// the raw 32-byte SHA-256 output over the exact request body bytes.
	public func putTag(nonce: Data, bodyDigest: Data) -> Data {
		let key = SymmetricKey(data: authKey.keyData)
		let message = Self.putLabel + Data(address.utf8) + nonce + bodyDigest
		let mac = HMAC<SHA256>.authenticationCode(for: message, using: key)
		return Data(mac)
	}
}

// MARK: - Wire format

extension MailboxGrant {
	/// The peer-to-peer carriage form — a deterministic-CBOR map, nested
	/// inside `AgentUpdateV2.grants` (see `DeterministicCbor`'s doc comment
	/// for why the keys are short strings, not integers).
	private struct Archive: Codable {
		let authKey: Data  // TypedKeyMaterial.wireFormat: 1 algorithm byte + 32 key bytes
		let serviceHost: String
		let expiration: UInt32  // RoundedDate.hoursSinceEpoch

		//WIRE-FROZEN: never change a raw value once shipped.
		enum CodingKeys: String, CodingKey {
			case authKey = "k"
			case serviceHost = "h"
			case expiration = "e"
		}
	}

	public var wireFormat: Data {
		get throws {
			try DeterministicCbor.encode(
				Archive(
					authKey: authKey.wireFormat,
					serviceHost: serviceHost,
					expiration: expiration.hoursSinceEpoch
				)
			)
		}
	}

	public init(wireFormat: Data) throws {
		let archive = try DeterministicCbor.decode(Archive.self, from: wireFormat)
		try self.init(
			authKey: TypedKeyMaterial(wireFormat: archive.authKey),
			serviceHost: archive.serviceHost,
			expiration: RoundedDate(hoursSinceEpoch: archive.expiration)
		)
	}
}

// MARK: - ProtocolAddress bridge

extension ProtocolAddress {
	/// Non-nil when `identifier` decodes as a mailbox grant's `authKey`
	/// (exactly 32 raw bytes) rather than a legacy `crypto.randomUUID()`
	/// address (36 characters, which decode as base64url to 27 bytes since
	/// `-` is in the alphabet — the lengths never collide).
	///
	/// This is the transitional carriage for surfaces that cannot take a
	/// wire-shape change (`PQAppWelcome`/`PQAnchorWelcome`/handoffs — see
	/// docs/attachment-mailbox-delivery.md, "Wire types"): only an `authKey`
	/// ever rides `identifier` in this format, never the derived `address`
	/// — the address is also 32 raw bytes and indistinguishable by shape, so
	/// the discrimination is sound only because both ends derive it from the
	/// key. `init(mailboxGrant:)`, below, is the only sanctioned way to build
	/// a grant-bearing `ProtocolAddress`; nothing else should hand-construct
	/// one with a base64url identifier.
	public var mailboxGrant: MailboxGrant? {
		guard let keyData = try? Data(base64URLEncoded: identifier),
			keyData.count == TypedKeyMaterial.Algorithms.hmacSha256.contentByteSize,
			let authKey = try? TypedKeyMaterial(
				algorithm: .hmacSha256,
				symmetricKey: SymmetricKey(data: keyData)
			)
		else {
			return nil
		}
		return try? MailboxGrant(
			authKey: authKey,
			serviceHost: serviceHost,
			expiration: expiration
		)
	}

	/// Builds the transitional carriage of `mailboxGrant` — see `mailboxGrant`.
	public init(mailboxGrant: MailboxGrant) {
		self.init(
			identifier: mailboxGrant.authKey.keyData.base64URLEncoded(padded: false),
			serviceHost: mailboxGrant.serviceHost,
			expiration: mailboxGrant.expiration
		)
	}
}
