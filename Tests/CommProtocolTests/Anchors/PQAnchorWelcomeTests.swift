//
//  PQAnchorWelcomeTests.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 7/17/26.
//

import AtprotoTypes
import AtprotoTypesMocks
import CommProtocol
import CommProtocolMocks
import CryptoKit
import Foundation
import Testing

struct PQAnchorWelcomeTests {
	let alexDID = Atproto.DID.mock()
	let alexPrivateAnchor: PrivateActiveAnchor
	let blairDID = Atproto.DID.mock()
	let blairPrivateAnchor: PrivateActiveAnchor

	init() throws {
		alexPrivateAnchor = .create(for: alexDID)
		blairPrivateAnchor = .create(for: blairDID)
	}

	private func makeReply(
		keyMaterial: PQEstablishmentKeyMaterial,
		recipient: PublicAnchor
	) throws -> (PrivateAnchorAgent, PQAnchorWelcome, PQAnchorWelcome.Content) {
		try blairPrivateAnchor.createPQAnchorWelcome(
			agentUpdate: .mock(),
			keyMaterial: keyMaterial,
			mlsWelcomeMessage: SymmetricKey(size: .bits256).rawRepresentation,
			newAgentKey: AgentPrivateKey(),
			recipient: recipient,
			newSeqNo: .random(in: .min...(.max))
		)
	}

	@Test func testPQAnchorExchange() throws {
		let keyMaterial = PQEstablishmentKeyMaterial.mock()
		let (blairReplyAgent, reply, _) = try makeReply(
			keyMaterial: keyMaterial,
			recipient: alexPrivateAnchor.publicAnchor
		)

		//wire round-trip before verification, as the recipient sees it
		let received = try PQAnchorWelcome.finalParse(reply.wireFormat)

		let verifiedReply = try blairPrivateAnchor.publicKey
			.verify(
				pqReply: received,
				recipient: alexPrivateAnchor.publicAnchor,
			)
		#expect(verifiedReply.agent.agentKey == blairReplyAgent.publicKey)
		//the establishment key material survives the round trip intact
		#expect(verifiedReply.welcome.keyMaterial == keyMaterial)
		#expect(
			verifiedReply.welcome.keyMaterial.bootstrapKpCommitment.digest.count == 32
		)
	}

	@Test func testWrongRecipientFailsVerification() throws {
		let (_, reply, _) = try makeReply(
			keyMaterial: .mock(),
			recipient: alexPrivateAnchor.publicAnchor
		)

		//recipient binding: a welcome addressed to Alex must not verify for Casey
		let caseyPrivateAnchor = PrivateActiveAnchor.create(for: Atproto.DID.mock())
		#expect(throws: (any Error).self) {
			_ = try blairPrivateAnchor.publicKey.verify(
				pqReply: reply,
				recipient: caseyPrivateAnchor.publicAnchor
			)
		}
	}

	@Test func testTamperedPackageFailsVerification() throws {
		let (_, reply, _) = try makeReply(
			keyMaterial: .mock(),
			recipient: alexPrivateAnchor.publicAnchor
		)

		//flip one byte of the signed package: the anchor signature must fail
		var tampered = reply.second
		tampered[tampered.count / 2] ^= 0x01
		let forged = PQAnchorWelcome(first: reply.first, second: tampered)
		#expect(throws: (any Error).self) {
			_ = try blairPrivateAnchor.publicKey.verify(
				pqReply: forged,
				recipient: alexPrivateAnchor.publicAnchor
			)
		}
	}

	@Test func testClassicalWelcomeIsNotAPQWelcome() throws {
		//domain separation: a classical AnchorWelcome's bytes must never
		//survive the PQ parse+verify chain (distinct layout AND distinct
		//signature discriminators — either alone must kill it)
		let (_, classicalReply, _) = try blairPrivateAnchor.createAnchorWelcome(
			agentUpdate: .mock(),
			keyPackageData: SymmetricKey(size: .bits256).rawRepresentation,
			mlsWelcomeMessage: SymmetricKey(size: .bits256).rawRepresentation,
			newAgentKey: AgentPrivateKey(),
			recipient: alexPrivateAnchor.publicAnchor,
			newSeqNo: .random(in: .min...(.max))
		)

		#expect(throws: (any Error).self) {
			_ = try blairPrivateAnchor.publicKey.verify(
				pqReply: try PQAnchorWelcome.finalParse(classicalReply.wireFormat),
				recipient: alexPrivateAnchor.publicAnchor
			)
		}
	}
}
