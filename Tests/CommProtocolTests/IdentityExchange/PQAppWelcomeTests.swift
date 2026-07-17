//
//  PQAppWelcomeTests.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 7/17/26.
//

import CommProtocol
import CommProtocolMocks
import CryptoKit
import Foundation
import Testing

struct PQAppWelcomeTests {
	@Test func testValidation() throws {
		let myAgent = AgentPrivateKey()
		let keyMaterial = PQEstablishmentKeyMaterial.mock()

		let mockWelcome = try PQAppWelcome.mock(
			remoteAgentKey: myAgent.publicKey,
			keyMaterial: keyMaterial
		)

		//wire round-trip via Combined, as the recipient sees it
		let combined = PQAppWelcome.Combined(
			appWelcome: mockWelcome,
			mlsMessageData: SymmetricKey(size: .bits256).rawRepresentation
		)
		let received = try PQAppWelcome.Combined.finalParse(combined.wireFormat)

		let validated = try received.appWelcome.validated(
			myAgent: myAgent.publicKey
		)

		#expect(
			validated.coreIdentity
				== mockWelcome.introduction.signedIdentity
				.content)
		#expect(
			validated.introContents == mockWelcome.introduction.signedContents.content)
		#expect(validated.welcomeContent == mockWelcome.signedContent.content)
		//the establishment key material survives the round trip intact
		#expect(validated.welcomeContent.keyMaterial == keyMaterial)
	}

	@Test func testClassicalAppWelcomeIsNotAPQAppWelcome() throws {
		//domain separation: a classical AppWelcome's bytes must never survive
		//the PQ parse+validate chain
		let myAgent = AgentPrivateKey()
		let classicalWelcome = try AppWelcome.mock(
			remoteAgentKey: myAgent.publicKey,
			keyPackageData: SymmetricKey(size: .bits256).rawRepresentation
		)

		#expect(throws: (any Error).self) {
			_ = try PQAppWelcome.finalParse(classicalWelcome.wireFormat)
				.validated(myAgent: myAgent.publicKey)
		}
	}
}
