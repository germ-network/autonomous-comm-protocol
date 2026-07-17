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
		let keyMaterial = try PQEstablishmentKeyMaterial.mock()

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
		//whole-struct equality holds across the wire round trip because
		//createPQAppWelcome stamps sentTime `.now.wireNormalized`
		#expect(validated.welcomeContent == mockWelcome.signedContent.content)
		//the establishment key material survives the round trip intact
		#expect(validated.welcomeContent.keyMaterial == keyMaterial)
	}

	@Test func testClassicalAppWelcomeIsNotAPQAppWelcome() throws {
		//domain separation: a classical AppWelcome's bytes must never survive
		//the PQ parse+validate chain (dies at parse — the classical fifth
		//element's bytes cannot decode as the PQ key-material pair)
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

	@Test func testPQAppWelcomeIsNotAClassicalAppWelcome() throws {
		//the reverse direction: a PQ welcome's bytes must not survive the
		//CLASSICAL parse+validate chain either (the PQ fifth element leaves
		//the commitment bytes trailing a classical parse)
		let myAgent = AgentPrivateKey()
		let pqWelcome = try PQAppWelcome.mock(
			remoteAgentKey: myAgent.publicKey,
			keyMaterial: try .mock()
		)

		#expect(throws: (any Error).self) {
			_ = try AppWelcome.finalParse(pqWelcome.wireFormat)
				.validated(myAgent: myAgent.publicKey)
		}
	}

	@Test func testTamperedCommitmentFailsValidation() throws {
		//the PR's core claim, negatively controlled: the bootstrap-KP
		//commitment rides INSIDE the agent-signed region, so flipping one of
		//its bytes after signing must fail validation — a post-establishment
		//channel adversary cannot substitute the PQ key material's binding.
		let myAgent = AgentPrivateKey()
		let welcome = try PQAppWelcome.mock(
			remoteAgentKey: myAgent.publicKey,
			keyMaterial: try .mock()
		)

		let original = welcome.signedContent.content
		var flipped = original.keyMaterial.bootstrapKpCommitment.digest
		flipped[flipped.startIndex] ^= 0x01
		let tamperedContent = try PQAppWelcome.Content(
			first: original.groupId,
			second: original.agentData,
			third: original.seqNo,
			fourth: original.sentTime,
			fifth: try PQEstablishmentKeyMaterial(
				keyPackageData: original.keyMaterial.keyPackageData,
				bootstrapKpCommitment: flipped
			)
		)
		//tampered content, ORIGINAL signature
		let forged = try PQAppWelcome(
			first: welcome.introduction,
			second: try .init(
				first: tamperedContent,
				second: welcome.signedContent.second
			)
		)

		#expect(throws: (any Error).self) {
			_ = try forged.validated(myAgent: myAgent.publicKey)
		}
	}

	@Test func testWrongRecipientAgentFailsValidation() throws {
		//recipient binding: the welcome names the recipient agent in its
		//delegation context, so validating as a DIFFERENT agent must throw
		//(no welcome replay/redirect across the recipient's agents)
		let myAgent = AgentPrivateKey()
		let welcome = try PQAppWelcome.mock(
			remoteAgentKey: myAgent.publicKey,
			keyMaterial: try .mock()
		)

		#expect(throws: (any Error).self) {
			_ = try welcome.validated(myAgent: AgentPrivateKey().publicKey)
		}
	}
}
