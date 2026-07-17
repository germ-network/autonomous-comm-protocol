//
//  PQAppWelcome+Mock.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 7/17/26.
//

import CommProtocol
import CryptoKit
import Foundation

extension PQAppWelcome {
	static public func mock(
		remoteAgentKey: AgentPublicKey,
		keyMaterial: PQEstablishmentKeyMaterial
	) throws -> PQAppWelcome {
		let (identityKey, signedIdentity) =
			try Mocks
			.mockIdentity()

		let groupId = DataIdentifier(width: .bits256)

		let (agentKey, introduction) =
			try identityKey
			.createNewDelegate(
				signedIdentity: signedIdentity,
				identityMutable: .mock(),
				agentType: .welcome(
					remoteAgentId: remoteAgentKey,
					groupId: groupId
				)
			)

		return try agentKey.createPQAppWelcome(
			introduction: introduction,
			agentData: .mock(),
			groupId: groupId,
			keyMaterial: keyMaterial
		)
	}
}

extension PQEstablishmentKeyMaterial {
	static public func mock() -> PQEstablishmentKeyMaterial {
		.init(
			keyPackageData: SymmetricKey(size: .bits256).rawRepresentation,
			bootstrapKpCommitment: .init(
				prefix: .sha256,
				over: SymmetricKey(size: .bits256).rawRepresentation
			)
		)
	}
}
