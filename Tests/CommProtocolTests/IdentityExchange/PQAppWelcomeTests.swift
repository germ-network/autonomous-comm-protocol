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
		//Field-wise, not whole-struct equality: Date's linear encoding stores
		//timeIntervalSince1970.bitPattern, but Date equates on
		//timeIntervalSinceReferenceDate, and the epoch conversion does not
		//always round-trip bit-exactly in Double — a pre-existing sub-µs wart,
		//meaningless on the wire, that whole-struct equality would flake on.
		let original = mockWelcome.signedContent.content
		#expect(validated.welcomeContent.groupId == original.groupId)
		#expect(validated.welcomeContent.agentData == original.agentData)
		#expect(validated.welcomeContent.seqNo == original.seqNo)
		#expect(
			abs(
				validated.welcomeContent.sentTime
					.timeIntervalSince(original.sentTime)) < 0.001
		)
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
