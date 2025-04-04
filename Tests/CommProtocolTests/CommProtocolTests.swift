//
//  EncodingTests.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 7/31/24.
//

import CommProtocol
import CryptoKit
import Foundation
import Testing

///exercise the public api
struct APITests {
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
				helloData: .mock(),
				for: signedIdentity.content.id
			)
		)

	}

	@Test func testLifecycle() throws {
		let validated = try agentHello.validated()
	}

	@Test func testResource() throws {
		let resource = Resource.mock()
		let resourceURL = resource.url
		#expect(resourceURL?.host() == resource.host)
		#expect(resourceURL?.scheme == "https")
		#expect(resourceURL?.path() == "/api/card/fetch/" + resource.identifier)

		let keyFragment = try #require(resourceURL?.fragment())
		let keyData = try #require(Data(base64URLEncoded: keyFragment))
		#expect(SymmetricKey(data: keyData) == resource.symmetricKey)
	}

	@Test func testAddress() throws {
		let addressA = ProtocolAddress.mock()
		let addressB = ProtocolAddress.mock()
		#expect(addressA.hashValue == addressA.hashValue)
		#expect(addressA.hashValue != addressB.hashValue)
	}
}
