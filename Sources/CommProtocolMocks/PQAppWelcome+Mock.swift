//
//  PQAppWelcome+Mock.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 7/17/26.
//

import CommProtocol
import Foundation

extension PQAppWelcome {
	static public func mock(
		remoteAgentKey: AgentPublicKey,
		keyMaterial: PQEstablishmentKeyMaterial
	) throws -> PQAppWelcome {
		let (identityKey, signedIdentity) =
			try Mocks
			.mockIdentity()

		let (agentKey, introduction) =
			try identityKey
			.createNewDelegate(
				signedIdentity: signedIdentity,
				identityMutable: .mock(),
				agentType: .pqCardEstablishment(
					remoteAgentId: remoteAgentKey
				)
			)

		return try agentKey.createPQAppWelcome(
			introduction: introduction,
			agentData: .mock(),
			keyMaterial: keyMaterial
		)
	}
}
