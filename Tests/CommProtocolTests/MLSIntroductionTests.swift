//
//  MLSIntroductionTests.swift
//  CommProtocol
//

import CryptoKit
import Foundation
import Testing

@testable import CommProtocol

struct MLSIntroductionTests {
	let classicalIntroduction = MLSIntroduction(
		suite: .mlsCurve25519ChaChaPoly,
		kemPublicKeyData: Data(repeating: 0x11, count: 32),
		encodedKeyPackage: Data(repeating: 0x22, count: 64)
	)

	@Test func testClassicalRoundTrip() throws {
		let decoded = try MLSIntroduction.finalParse(classicalIntroduction.wireFormat)
		#expect(decoded == classicalIntroduction)
	}

	///The PQ shim is wire-indistinguishable from a classical entry: it leads with the
	///classical key-material tag and decodes as a classical-suite entry whose opaque key
	///package is preserved intact.
	@Test func testPostQuantumShimRoundTrip() throws {
		let keyPackage = Data([0xFD, 0xEA]) + Data(repeating: 0x44, count: 200)
		let shim = MLSIntroduction.postQuantumShim(
			kemPublicKeyData: Data(repeating: 0x33, count: 32),
			encodedKeyPackage: keyPackage
		)
		let encoded = try shim.wireFormat
		#expect(
			encoded.first
				== TypedKeyMaterial.Algorithms
				.hpkeEncapCurve25519Sha256ChachaPoly.rawValue)

		let decoded = try MLSIntroduction.finalParse(encoded)
		#expect(decoded.suite == .mlsCurve25519ChaChaPoly)
		#expect(decoded.encodedKeyPackage == keyPackage)
	}

	//the opaque key package is bounded by the wire's UInt16 length field
	@Test func testKeyPackageBounds() throws {
		let atLimit = MLSIntroduction.postQuantumShim(
			kemPublicKeyData: Data(repeating: 0x33, count: 32),
			encodedKeyPackage: Data(repeating: 0x44, count: Int(UInt16.max))
		)
		let decoded = try MLSIntroduction.finalParse(atLimit.wireFormat)
		#expect(decoded == atLimit)

		let overLimit = MLSIntroduction.postQuantumShim(
			kemPublicKeyData: Data(repeating: 0x33, count: 32),
			encodedKeyPackage: Data(repeating: 0x44, count: Int(UInt16.max) + 1)
		)
		#expect(throws: LinearEncodingError.bodyTooLarge) {
			try overLimit.wireFormat
		}
	}

	//the shim inherits the classical 32-byte header-key width at encode time
	@Test func testShimKemKeyWidthEnforced() throws {
		let malformed = MLSIntroduction.postQuantumShim(
			kemPublicKeyData: Data(repeating: 0x33, count: 31),
			encodedKeyPackage: Data([0xFD, 0xEA]) + Data(repeating: 0x44, count: 100)
		)
		#expect(throws: LinearEncodingError.invalidTypedKey) {
			try malformed.wireFormat
		}
	}
}
