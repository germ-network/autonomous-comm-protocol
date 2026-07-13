//
//  AgentHelloDualOfferTests.swift
//  CommProtocol
//

import CommProtocolMocks
import CryptoKit
import Foundation
import Testing

@testable import CommProtocol

///Mirror of the deployed codec: MLSIntroduction as a plain TypedKeyMaterial + Data
///pair, inside a triple. Because the PQ entry is a legacy-shaped entry, this
///already-shipped shape parses a dual offer unchanged.
private struct LegacyMLSIntroduction: LinearEncodedPair {
	let first: TypedKeyMaterial
	let second: Data

	init(first: TypedKeyMaterial, second: Data) throws {
		self.first = first
		self.second = second
	}
}

private struct LegacyNewAgentData: LinearEncodedTriple {
	let first: AgentUpdate
	let second: [LegacyMLSIntroduction]
	let third: Date

	init(first: AgentUpdate, second: [LegacyMLSIntroduction], third: Date) throws {
		self.first = first
		self.second = second
		self.third = third
	}
}

struct AgentHelloDualOfferTests {
	//deterministic fixtures for byte-level assertions
	let agentUpdate = AgentUpdate(
		version: .init(major: 1, minor: 2, patch: 3),
		isAppClip: false,
		addresses: []
	)
	let expiration = Date(timeIntervalSince1970: 1_752_000_000)

	let classicalIntroduction = MLSIntroduction(
		suite: .mlsCurve25519ChaChaPoly,
		kemPublicKeyData: Data(repeating: 0x11, count: 32),
		encodedKeyPackage: Data(repeating: 0x22, count: 64)
	)

	//a PQ key package advertises its suite (0xFDEA) inside the opaque blob
	let pqShimIntroduction = MLSIntroduction.postQuantumShim(
		kemPublicKeyData: Data(repeating: 0x33, count: 32),
		encodedKeyPackage: Data([0xFD, 0xEA]) + Data(repeating: 0x44, count: 100)
	)

	var classicalOnlyData: AgentHello.NewAgentData {
		.init(
			agentUpdate: agentUpdate,
			keyChoices: [classicalIntroduction],
			expiration: expiration
		)
	}

	var dualOfferData: AgentHello.NewAgentData {
		.init(
			agentUpdate: agentUpdate,
			keyChoices: [classicalIntroduction, pqShimIntroduction],
			expiration: expiration
		)
	}

	///The dual offer is the classical-only offer with the list count bumped and the PQ
	///entry spliced in after the classical entry: the classical entry's bytes and
	///position are unchanged.
	@Test func testDualOfferSplice() throws {
		let classicalOnly = try classicalOnlyData.wireFormat
		let dual = try dualOfferData.wireFormat

		let countIndex = try agentUpdate.wireFormat.count
		#expect(classicalOnly[countIndex] == 1)
		#expect(dual[countIndex] == 2)

		let classicalElement = try classicalIntroduction.wireFormat
		let pqElement = try pqShimIntroduction.wireFormat

		var expected = classicalOnly
		expected[countIndex] = 2
		expected.insert(
			contentsOf: pqElement,
			at: countIndex + 1 + classicalElement.count
		)
		#expect(dual == expected)
	}

	///Lock the card encoding against drift: these bytes must match what the pre-shim
	///release produces for the same content (v1.3.0, d2106a8).
	@Test func testClassicalOnlyGolden() throws {
		let encoded = try classicalOnlyData.wireFormat
		#expect(encoded == Data(hexString: Self.classicalOnlyGoldenHex))
	}

	///The whole point of the shim: a decoder that predates it still parses a dual offer,
	///because every entry is a well-formed legacy entry.
	@Test func testLegacyDecoderParsesDualOffer() throws {
		let decoded = try LegacyNewAgentData.finalParse(dualOfferData.wireFormat)
		#expect(decoded.first == agentUpdate)
		#expect(decoded.second.count == 2)
		//the classical entry is first and intact
		#expect(decoded.second.first?.second == classicalIntroduction.encodedKeyPackage)
		//the PQ package survives as opaque bytes an old decoder simply won't interpret
		#expect(decoded.second.last?.second == pqShimIntroduction.encodedKeyPackage)
		#expect(decoded.third == expiration)
	}

	///Consumers detect the PQ entry by inspecting the key package (here: the suite id it
	///advertises internally), not the wrapper. Without that capability they take index 0.
	@Test func testSelectionByKeyPackage() throws {
		let choices = dualOfferData.keyChoices
		let pqSuiteTag = Data([0xFD, 0xEA])
		let pqCapableChoice = choices.first {
			$0.encodedKeyPackage.starts(with: pqSuiteTag)
		}
		#expect(pqCapableChoice == pqShimIntroduction)

		//a consumer that can't read the key package falls back to the first entry
		#expect(choices.first == classicalIntroduction)
	}

	///End to end through the signature: the agent signature covers the PQ entry.
	@Test func testDualOfferAgentHello() throws {
		let (hello, _, agentKey, signedIdentity) = try Self.dualOfferHello(
			dualOfferData
		)
		let encoded = try hello.wireFormat
		let validated = try AgentHello.finalParse(encoded).validated()
		#expect(validated.agentKey == agentKey.publicKey)
		#expect(validated.coreIdentity == signedIdentity.content)
		#expect(validated.agentData.keyChoices.count == 2)
		#expect(validated.agentData.keyChoices[1] == pqShimIntroduction)
	}

	///Tampering with the PQ key package inside the encoded card fails validation.
	@Test func testTamperedPQEntryFailsValidation() throws {
		let (hello, _, _, _) = try Self.dualOfferHello(dualOfferData)
		var encoded = try hello.wireFormat

		let pqRange = try #require(
			encoded.firstRange(of: try pqShimIntroduction.wireFormat)
		)
		encoded[pqRange.upperBound - 1] ^= 0xFF

		let tampered = try AgentHello.finalParse(encoded)
		#expect(throws: ProtocolError.authenticationError) {
			try tampered.validated()
		}
	}

	///Stripping the PQ entry (downgrade to classical-only) fails validation.
	@Test func testStrippedPQEntryFailsValidation() throws {
		let (hello, _, _, _) = try Self.dualOfferHello(dualOfferData)
		var encoded = try hello.wireFormat

		let pqRange = try #require(
			encoded.firstRange(of: try pqShimIntroduction.wireFormat)
		)
		let classicalRange = try #require(
			encoded.firstRange(of: try classicalIntroduction.wireFormat)
		)
		encoded.removeSubrange(pqRange)
		#expect(encoded[classicalRange.lowerBound - 1] == 2)
		encoded[classicalRange.lowerBound - 1] = 1

		let stripped = try AgentHello.finalParse(encoded)
		#expect(stripped.signedAgentData.content.keyChoices.count == 1)
		#expect(throws: ProtocolError.authenticationError) {
			try stripped.validated()
		}
	}

	private static func dualOfferHello(
		_ agentData: AgentHello.NewAgentData
	) throws -> (
		AgentHello, IdentityPrivateKey, AgentPrivateKey, SignedObject<CoreIdentity>
	) {
		let (identityKey, signedIdentity) = try Mocks.mockIdentity()
		let (agentKey, introduction) = try identityKey.createNewDelegate(
			signedIdentity: signedIdentity,
			identityMutable: .mock(),
			agentType: .hello
		)
		let hello = try agentKey.createAgentHello(
			introduction: introduction,
			signedAgentData: try agentKey.sign(
				helloData: agentData,
				for: signedIdentity.content.id
			)
		)
		return (hello, identityKey, agentKey, signedIdentity)
	}

	//pinned against the pre-shim encoding of the same content (v1.3.0, d2106a8)
	private static let classicalOnlyGoldenHex =
		"010203000000010411111111111111111111111111111111111111111111111111"
		+ "111111111111114022222222222222222222222222222222222222222222222222"
		+ "222222222222222222222222222222222222222222222222222222222222222222"
		+ "22222222222241da1b5980000000"
}

extension Data {
	fileprivate init?(hexString: String) {
		guard hexString.count.isMultiple(of: 2) else { return nil }
		var bytes = [UInt8]()
		bytes.reserveCapacity(hexString.count / 2)
		var index = hexString.startIndex
		while index < hexString.endIndex {
			let next = hexString.index(index, offsetBy: 2)
			guard let byte = UInt8(hexString[index..<next], radix: 16) else {
				return nil
			}
			bytes.append(byte)
			index = next
		}
		self.init(bytes)
	}
}
