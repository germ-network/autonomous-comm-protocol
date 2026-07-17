//
//  PQAnchorWelcomeTests.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 7/17/26.
//

import AtprotoTypes
import AtprotoTypesMocks
import CommProtocolMocks
import CryptoKit
import Foundation
import Testing

@testable import CommProtocol

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
		let keyMaterial = try PQEstablishmentKeyMaterial.mock()
		let (blairReplyAgent, reply, content) = try makeReply(
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
		//pin every Verified field against the created content (Data fields are
		//interchangeable by type — a wrong-field regression would type-check);
		//sentTime equality holds because create stamps it `.now.wireNormalized`
		#expect(verifiedReply.welcome.keyMaterial == keyMaterial)
		#expect(verifiedReply.mlsWelcomeData == content.mlsWelcomeData)
		#expect(verifiedReply.welcome.seqNo == content.welcome.seqNo)
		#expect(verifiedReply.welcome.agentUpdate == content.welcome.agentUpdate)
		#expect(verifiedReply.welcome.sentTime == content.welcome.sentTime)
	}

	@Test func testWrongRecipientFailsVerification() throws {
		let (_, reply, _) = try makeReply(
			keyMaterial: try .mock(),
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
			keyMaterial: try .mock(),
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
		//domain separation, classical→PQ direction. What this proves: the OUTER
		//signature discriminator ("AnchorReply.*" vs "PQAnchorReply.*") rejects
		//the classical welcome — the outer shapes are byte-identical, so parse
		//succeeds, and verifyPackage checks the signature BEFORE parsing the
		//package, so the Welcome-layout divergence is never reached here (it is
		//a second, independent defense, not exercised by this test).
		let (_, classicalReply, _) = try blairPrivateAnchor.createAnchorWelcome(
			agentUpdate: .mock(),
			keyPackageData: SymmetricKey(size: .bits256).rawRepresentation,
			mlsWelcomeMessage: SymmetricKey(size: .bits256).rawRepresentation,
			newAgentKey: AgentPrivateKey(),
			recipient: alexPrivateAnchor.publicAnchor,
			newSeqNo: .random(in: .min...(.max))
		)

		let parsed = try PQAnchorWelcome.finalParse(classicalReply.wireFormat)
		//ProtocolError (verification), not LinearEncodingError (parse)
		#expect(throws: ProtocolError.self) {
			_ = try blairPrivateAnchor.publicKey.verify(
				pqReply: parsed,
				recipient: alexPrivateAnchor.publicAnchor
			)
		}
	}

	@Test func testPQWelcomeIsNotAClassicalWelcome() throws {
		//domain separation, the reverse (PQ→classical) direction: a PQ welcome's
		//bytes must not verify on the classical route either (cross-route
		//replay/downgrade). Same mechanism — the classical verify reconstructs
		//its own discriminator, so the PQ outer signature never matches.
		let (_, pqReply, _) = try makeReply(
			keyMaterial: try .mock(),
			recipient: alexPrivateAnchor.publicAnchor
		)

		let parsed = try AnchorWelcome.finalParse(pqReply.wireFormat)
		//ProtocolError (verification), not LinearEncodingError (parse)
		#expect(throws: ProtocolError.self) {
			_ = try blairPrivateAnchor.publicKey.verify(
				reply: parsed,
				recipient: alexPrivateAnchor.publicAnchor
			)
		}
	}

	@Test func testForgedAgentSignatureFailsVerification() throws {
		//the INNER guard: an agent signature minted by a key the content does
		//not name must fail even when the outer anchor signature is genuine.
		//(The tamper test above breaks the OUTER signature, which throws before
		//the inner guard is reached — this is the only test that exercises it.)
		let (_, _, content) = try makeReply(
			keyMaterial: try .mock(),
			recipient: alexPrivateAnchor.publicAnchor
		)

		let mallory = AgentPrivateKey()
		let forgedPackage = PQAnchorWelcome.Package(
			first: content,
			second: try mallory.signer(
				content
					.agentSignatureBody(
						recipient: alexPrivateAnchor.publicAnchor
					)
					.wireFormat
			)
		)
		//outer anchor signature over the forged package, correctly minted
		let outerSignature = try blairPrivateAnchor.privateKey.signer(
			try PQAnchorWelcome.AnchorSignatureBody(
				encodedPackage: try forgedPackage.wireFormat,
				knownAnchor: blairPrivateAnchor.publicKey,
				recipient: alexPrivateAnchor.publicAnchor,
			).wireFormat
		)
		let forged = PQAnchorWelcome(
			first: outerSignature,
			second: try forgedPackage.wireFormat
		)

		//ProtocolError (verification), not LinearEncodingError (parse)
		#expect(throws: ProtocolError.self) {
			_ = try blairPrivateAnchor.publicKey.verify(
				pqReply: forged,
				recipient: alexPrivateAnchor.publicAnchor
			)
		}
	}
}

struct PQEstablishmentKeyMaterialWireTests {
	//The commitment's wire contract: prefix byte 0x01 (sha256) + exactly 32
	//bytes, frozen independent of how DigestTypes evolves. Today the 0x02 case
	//is rejected by TypedDigest's own unknown-prefix parse; once DigestTypes
	//grows a second case for any unrelated feature, the .sha256 pin in
	//PQEstablishmentKeyMaterial's parse init is what keeps this red — the
	//session layer accepts exactly SHA-256/32, so any other digest must die
	//at decode, not deep in the A.4 side-band.
	private func encoded(prefix: UInt8, digestBytes: Int) throws -> Data {
		let kp = SymmetricKey(size: .bits256).rawRepresentation
		var bytes = Data()
		bytes.append(UInt8(kp.count))  //OptionalData short-form length prefix
		bytes.append(kp)
		bytes.append(prefix)
		bytes.append(SymmetricKey(size: .bits256).rawRepresentation.prefix(digestBytes))
		return bytes
	}

	@Test func testRoundTrip() throws {
		let material = try PQEstablishmentKeyMaterial.mock()
		let received = try PQEstablishmentKeyMaterial.finalParse(material.wireFormat)
		#expect(received == material)
	}

	@Test func testUnknownDigestPrefixFailsParse() throws {
		#expect(throws: (any Error).self) {
			_ = try PQEstablishmentKeyMaterial.finalParse(
				try encoded(prefix: 0x02, digestBytes: 32)
			)
		}
	}

	@Test func testTruncatedDigestFailsParse() throws {
		#expect(throws: (any Error).self) {
			_ = try PQEstablishmentKeyMaterial.finalParse(
				try encoded(prefix: 0x01, digestBytes: 31)
			)
		}
	}

	@Test func testEmptyKeyPackageIsRejectedAtCreate() throws {
		//an empty key package encodes as the OptionalData none-marker ([0]),
		//which the RECIPIENT's parse rejects as requiredValueMissing — the
		//create-side guard converts that remote parse failure into a local,
		//immediate error before the welcome ever goes out
		#expect(throws: (any Error).self) {
			_ = try PQEstablishmentKeyMaterial(
				keyPackageData: Data(),
				bootstrapKpCommitment: try TypedDigest.mock().digest
			)
		}
	}
}
