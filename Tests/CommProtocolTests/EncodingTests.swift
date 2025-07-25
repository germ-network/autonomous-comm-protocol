//
//  EncodingTests.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 7/31/24.
//

import Foundation
import Testing

@testable import CommProtocol

struct EncodingTests {

	@Test func testSemVer() throws {
		// Write your test here and use APIs like `#expect(...)` to check expected conditions.
		let semVer = SemanticVersion.mock()
		let encodedSemVer = try semVer.wireFormat
		let decodedSemVer = try SemanticVersion.finalParse(encodedSemVer)

		#expect(semVer == decodedSemVer)
	}

	@Test func testOptString() throws {
		let nilString: String? = nil
		let encodedNil = try OptionalString(nilString).wireFormat
		let decodedNil: OptionalString = try encodedNil.parseWireFormat()
		#expect(decodedNil.string == nil)

		let string = UUID().uuidString
		let encoded = try OptionalString(string).wireFormat
		let decoded = try OptionalString.finalParse(encoded)
		#expect(decoded.string == string)
	}

	@Test func testBool() throws {
		let encodedFalse = false.wireFormat
		#expect(encodedFalse.count == 1)
		let decoded = try Bool.finalParse(encodedFalse)
		#expect(!decoded)

		let encodedTrue = true.wireFormat
		#expect(encodedTrue.count == 1)
		let decodedTrue = try Bool.finalParse(encodedTrue)
		#expect(decodedTrue)

		#expect(throws: LinearEncodingError.unexpectedData) {
			let _ = try Bool.finalParse(.init([2]))
		}
	}

	@Test func testAddress() throws {
		let address = ProtocolAddress.mock()
		let encoded = try address.wireFormat
		let decoded = try ProtocolAddress.finalParse(encoded)

		#expect(decoded == address)
	}

	@Test func testAddresses() throws {
		let single: [ProtocolAddress] = [.mock()]
		let encodedSingle = try single.wireFormat
		let decodedSingle = try [ProtocolAddress].finalParse(encodedSingle)
		#expect(decodedSingle == single)

		let double: [ProtocolAddress] = [.mock(), .mock()]
		let encodedDouble = try double.wireFormat
		let decodedDouble = try [ProtocolAddress].finalParse(encodedDouble)
		#expect(decodedDouble == double)
	}

	@Test func testResource() throws {
		let nilResource: Resource? = nil
		let encodedNil = try nilResource.wireFormat
		let decodedNil = try (Resource?).finalParse(encodedNil)
		#expect(decodedNil == nil)

		let resource: Resource = .mock()
		let encodedBare = try resource.wireFormat
		let decodedBare = try Resource.finalParse(encodedBare)
		#expect(resource == decodedBare)

		let encodedWrapped = try (resource as Resource?).wireFormat
		#expect(encodedWrapped.count == encodedBare.count + 1)
		let decodedWrapped = try (Resource?).finalParse(encodedWrapped)
	}

	@Test func testIdentityMutable() throws {
		let content: IdentityMutableData = .mock()
		let encoded = try content.wireFormat
		let decoded = try IdentityMutableData.finalParse(encoded)
		#expect(decoded == content)
	}

	//not currently used
	@Test func testSessionSuitesFixedEncoding() throws {
		for suite in SessionEncryptionSuites.allCases {
			#expect(suite.fixedWidth.count == 2)
			let decoded = try SessionEncryptionSuites(fixedWidth: suite.fixedWidth)
			#expect(suite == decoded)
		}
	}
}
