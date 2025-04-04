//
//  AgentHelloTests.swift
//  CommProtocol
//
//  Created by Mark Xue on 7/26/24.
//

import CryptoKit
import Foundation
import Testing

@testable import CommProtocol

struct AgentHelloTests {
	let identityKey: IdentityPrivateKey
	let signedIdentity: SignedObject<CoreIdentity>
	let agentKey: AgentPrivateKey
	let introduction: IdentityIntroduction
	let agentHello: AgentHello

	init() throws {
		(identityKey, signedIdentity) =
			try Mocks
			.mockIdentity()

		(agentKey, introduction) =
			try identityKey
			.createNewDelegate(
				signedIdentity: signedIdentity,
				identityMutable: .mock(),
				agentType: .hello
			)

		agentHello = try agentKey.createAgentHello(
			introduction: introduction,
			signedAgentData: try agentKey.sign(
				helloData: .mock(), for: signedIdentity.content.id
			)
		)
	}

	@Test func testAgentHello() throws {
		let encoded = try agentHello.wireFormat
		//Not as critical, but output for comparison
		print("AgentHello size \(encoded.count)")

		let reencoded = try AgentHello.finalParse(encoded)

		let validatedHello = try reencoded.validated()

		#expect(validatedHello.coreIdentity == signedIdentity.content)
		#expect(validatedHello.agentKey == agentKey.publicKey)
		#expect(validatedHello.mutableData == validatedHello.mutableData)
		#expect(validatedHello.agentData == agentHello.signedAgentData.content)

	}

	@Test func testAgentHelloFailure() throws {
		let agentData = agentHello.signedAgentData.content

		let modifedData = AgentUpdate(
			version: agentData.agentUpdate.version,
			isAppClip: !agentData.agentUpdate.isAppClip,  //invert
			addresses: agentData.agentUpdate.addresses
		)

		let modifiedTBS = AgentHello.NewAgentData(
			agentUpdate: modifedData,
			keyChoices: agentData.keyChoices,
			expiration: agentData.expiration
		)

		let modifiedSignedAgentData = SignedObject<AgentHello.NewAgentData>(
			content: modifiedTBS,
			signature: agentHello.signedAgentData.signature
		)

		let modifiedTBSHello = AgentHello(
			introduction: agentHello.introduction,
			signedAgentData: modifiedSignedAgentData
		)

		#expect(throws: ProtocolError.authenticationError) {
			let _ = try modifiedTBSHello.validated()
		}
	}
}
