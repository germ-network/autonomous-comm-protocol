//
//  TypedKeyTest.swift
//
//
//  Created by Mark @ Germ on 6/21/24.
//

import CryptoKit
import Foundation
import Testing

@testable import CommProtocol

struct TypedKeyTests {

	@Test func testSigning() async throws {
		let privateSigningKey = Curve25519.Signing.PrivateKey()

		let publicKey = privateSigningKey.publicKey
		let typedPublic = TypedKeyMaterial(typedKey: publicKey)
		let decodedPublic: Curve25519.Signing.PublicKey = try .init(
			wireFormat: typedPublic.wireFormat)
		#expect(publicKey.rawRepresentation == decodedPublic.rawRepresentation)

		#expect(throws: LinearEncodingError.self) {
			let _ = try Curve25519.KeyAgreement.PublicKey(
				wireFormat: typedPublic.wireFormat)
		}
	}

	@Test func testKeyAgreement() async throws {
		let privateSigningKey = Curve25519.KeyAgreement.PrivateKey()

		let publicKey = privateSigningKey.publicKey
		let typedPublic = TypedKeyMaterial(typedKey: publicKey)
		let decodedPublic: Curve25519.KeyAgreement.PublicKey = try .init(
			wireFormat: typedPublic.wireFormat)
		#expect(publicKey.rawRepresentation == decodedPublic.rawRepresentation)

		#expect(throws: LinearEncodingError.self) {
			let _ = try Curve25519.Signing.PublicKey(wireFormat: typedPublic.wireFormat)
		}
	}

	@Test func testSymmetric() async throws {
		let untyped256key = SymmetricKey(size: .bits256)
		let shortKey = SymmetricKey(size: .bits128)

		let typed = try TypedKeyMaterial(
			algorithm: .chaCha20Poly1305,
			symmetricKey: untyped256key)

		let _ = try TypedKeyMaterial(
			algorithm: .aesGCM256,
			symmetricKey: untyped256key)

		let received = try TypedKeyMaterial(wireFormat: typed.wireFormat)

		#expect(received.algorithm == .chaCha20Poly1305)
		#expect(received.keyData == untyped256key.rawRepresentation)

		#expect(throws: LinearEncodingError.self) {
			let _ = try TypedKeyMaterial(
				algorithm: .chaCha20Poly1305,
				symmetricKey: shortKey)
		}

		#expect(throws: LinearEncodingError.self) {
			let _ = try TypedKeyMaterial(
				prefix: .chaCha20Poly1305,
				checkedData: shortKey.rawRepresentation
			)
		}

		#expect(throws: LinearEncodingError.self) {
			let _ = try TypedKeyMaterial(
				algorithm: .hpkeEncapCurve25519Sha256ChachaPoly,
				symmetricKey: untyped256key)
		}
	}

	@Test func testEncapsulated() async throws {
		let senderPrivateKey = Curve25519.KeyAgreement.PrivateKey()
		let recipientPrivateKey = Curve25519.KeyAgreement.PrivateKey()

		let channelInfo = Data(UUID().uuidString.utf8)
		var hpkeSender = try HPKE.Sender(
			recipientKey: recipientPrivateKey.publicKey,
			ciphersuite: .Curve25519_SHA256_ChachaPoly,
			info: channelInfo,
			authenticatedBy: senderPrivateKey
		)
		let plaintext = UUID().uuidString
		let message = try hpkeSender.seal(Data(plaintext.utf8))

		let encapKey = hpkeSender.encapsulatedKey
		let wireFormat = try TypedKeyMaterial(
			encapAlgorithm: .hpkeEncapCurve25519Sha256ChachaPoly,
			data: encapKey
		).wireFormat
		let receivedFormat = try TypedKeyMaterial(wireFormat: wireFormat)
		#expect(receivedFormat.algorithm == .hpkeEncapCurve25519Sha256ChachaPoly)
		let receivedKey = receivedFormat.keyData

		var hpkeReceiver = try HPKE.Recipient(
			privateKey: recipientPrivateKey,
			ciphersuite: .Curve25519_SHA256_ChachaPoly,
			info: channelInfo,
			encapsulatedKey: receivedKey,
			authenticatedBy: senderPrivateKey.publicKey
		)

		let decrypted = try hpkeReceiver.open(message)
		#expect(decrypted == Data(plaintext.utf8))

		#expect(throws: LinearEncodingError.self) {
			let _ = try TypedKeyMaterial(
				encapAlgorithm: .aesGCM256,
				data: encapKey
			)
		}
	}

}
