//
//  AgentTypes.swift
//  CommProtocol
//
//  Created by Mark Xue on 8/14/24.
//

import CryptoKit
import Foundation

public enum AgentTypes {
    case hello
    case reply(agentId: AgentPublicKey, seed: Data)

    func generateContext(myAgentId: AgentPublicKey) throws -> TypedDigest? {
        switch self {
        case .hello: return nil
        case .reply(let agentId, let seed):
            var hasher = SHA256()
            hasher.update(data: agentId.wireFormat)
            hasher.update(data: myAgentId.wireFormat)
            hasher.update(data: seed)
            return try .init(prefix: .sha256, checkedData: hasher.finalize().data)
        }
    }
}
