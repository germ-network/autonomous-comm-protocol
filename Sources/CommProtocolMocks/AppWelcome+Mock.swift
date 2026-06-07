//
//  AppWelcome+Mock.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 2/9/25.
//

import CommProtocol
import Foundation

extension AppWelcome {
	static public func mock(
		remoteAgentKey: AgentPublicKey,
		keyPackageData: Data
	) throws -> AppWelcome {
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

		return try agentKey.createAppWelcome(
			introduction: introduction,
			agentData: .mock(),
			groupId: groupId,
			keyPackageData: keyPackageData
		)
	}
}
