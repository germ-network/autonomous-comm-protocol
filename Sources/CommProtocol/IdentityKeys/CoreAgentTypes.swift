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
	//The PQ card establishment introduction: binds the peer agent it answers
	//(cross-invitation anti-splice) but carries NO session seed. Used by BOTH sides
	//(the replier mints with it, the acceptor's `PQAppWelcome.validated` reconstructs
	//it), so a single seedless case suffices — there is no seed to differ between the
	//`.reply`/`.welcome` roles. The session identity is now the crate's LOCAL send-group
	//id and the welcome↔identity weld is the establishment handoff over
	//`sha256(welcome)`, so a per-session seed here is redundant (agent-signed Content +
	//the handoff already pin the establishment). No collision with `.reply`/`.welcome`:
	//those prepend a ≥16-byte non-empty `DataIdentifier`, so a 3-input context can never
	//equal this 2-input one.
	case pqCardEstablishment(remoteAgentId: AgentPublicKey)

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
		case .pqCardEstablishment(let remoteAgentId):
			var hasher = SHA256()
			hasher.update(data: remoteAgentId.wireFormat)
			hasher.update(data: myAgentId.wireFormat)
			return try .init(
				prefix: .sha256,
				checkedData: hasher.finalize().data
			)
		}
	}
}
