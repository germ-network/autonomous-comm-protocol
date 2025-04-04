//
//  AgentTypes.swift
//  CommProtocol
//
//  Created by Mark Xue on 8/14/24.
//

import CryptoKit
import Foundation

//only using this for the exchange, not subsequent proposals
public enum AgentTypes {
	case hello
	case reply(remoteAgentId: AgentPublicKey, seed: DataIdentifier)
	case welcome(remoteAgentId: AgentPublicKey, groupId: DataIdentifier)

	public func generateContext(
		myAgentId: AgentPublicKey
	) throws -> TypedDigest? {
		switch self {
		case .hello: return nil
		case .reply(let remoteAgentId, let base):
			var hasher = SHA256()
			hasher.update(data: base.identifier)
			hasher.update(data: remoteAgentId.wireFormat)
			hasher.update(data: myAgentId.wireFormat)
			return try .init(
				prefix: .sha256,
				checkedData: hasher.finalize().data
			)
		case .welcome(let remoteAgentId, let groupId):
			var hasher = SHA256()
			hasher.update(data: groupId.identifier)
			hasher.update(data: remoteAgentId.wireFormat)
			hasher.update(data: myAgentId.wireFormat)
			return try .init(
				prefix: .sha256,
				checkedData: hasher.finalize().data
			)
		}
	}
}
