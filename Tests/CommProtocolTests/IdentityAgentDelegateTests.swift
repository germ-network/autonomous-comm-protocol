//
//  IdentityAgentDelegateTests.swift
//  CommProtocol
//
//  Pins `IdentityPrivateKey.createAgentDelegate(for:context:)` — delegating an
//  agent key the caller already holds. Needed when the agent key must be chosen
//  before the delegation context is known (a PQ card session's receiver picks its
//  `newClientId` up front, then learns the session proposal context only after
//  the establishment handshake).
//

import CommProtocolMocks
import Foundation
import Testing

@testable import CommProtocol

struct IdentityAgentDelegateTests {
	let identityKey: IdentityPrivateKey
	let signedIdentity: SignedObject<CoreIdentity>

	init() throws {
		(identityKey, signedIdentity) = try Mocks.mockIdentity()
	}

	@Test func delegatesAPreMintedAgentKey() throws {
		let context = try TypedDigest.mock()
		//caller mints the agent key up front (the PQ-card `newClientId` case)
		let newAgent = AgentPrivateKey()

		let delegate = try identityKey.createAgentDelegate(
			for: newAgent.publicKey,
			context: context
		)

		//the delegate names the pre-minted key and validates under the identity
		#expect(delegate.newAgentId == newAgent.publicKey)
		let validated = try delegate.validate(
			knownIdentity: signedIdentity.content.id,
			context: context
		)
		#expect(validated == newAgent.publicKey)
	}

	@Test func rejectsWrongContext() throws {
		let newAgent = AgentPrivateKey()
		let delegate = try identityKey.createAgentDelegate(
			for: newAgent.publicKey,
			context: try TypedDigest.mock()
		)
		#expect(throws: (any Error).self) {
			//validation under a different context must fail the signature check
			_ = try delegate.validate(
				knownIdentity: signedIdentity.content.id,
				context: try TypedDigest.mock()
			)
		}
	}

	@Test func mintingVariantMatchesForVariant() throws {
		//the minting convenience now routes through the pre-minted-key path, so a
		//delegate built either way names and validates the same agent key
		let context = try TypedDigest.mock()
		let (minted, delegate) = try identityKey.createAgentDelegate(context: context)
		let viaFor = try identityKey.createAgentDelegate(
			for: minted.publicKey, context: context)

		#expect(delegate.newAgentId == viaFor.newAgentId)
		#expect(
			try delegate.validate(
				knownIdentity: signedIdentity.content.id, context: context)
				== (try viaFor.validate(
					knownIdentity: signedIdentity.content.id, context: context))
		)
	}
}
