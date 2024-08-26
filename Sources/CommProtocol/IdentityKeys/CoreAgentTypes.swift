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
    case reply(remoteAgentId: AgentPublicKey, seed: Data)
    case replacement(remoteAgentId: AgentPublicKey, base: Data)

    func generateContext(myAgentId: AgentPublicKey) throws -> TypedDigest? {
        switch self {
        case .hello: return nil
        case .reply(let remoteAgentId, let base),
            .replacement(let remoteAgentId, let base):
            var hasher = SHA256()
            hasher.update(data: remoteAgentId.wireFormat)
            hasher.update(data: myAgentId.wireFormat)
            hasher.update(data: base)
            return try .init(prefix: .sha256, checkedData: hasher.finalize().data)
        }
    }
}
