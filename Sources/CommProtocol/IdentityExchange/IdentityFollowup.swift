//
//  IdentityFollowup.swift
//
//
//  Created by Mark @ Germ on 6/27/24.
//

import Foundation

//Stapled to every message

//Not worth it yet to optimize out 3 bytes version + 1 byte isAppClip
public struct AgentUpdate: Sendable, Equatable {
    public let version: SemanticVersion
    public let isAppClip: Bool
    public let addresses: [ProtocolAddress]

    func formatForSigning(
        updateMessage: Data,
        context: TypedDigest
    ) throws -> Data {
        try wireFormat + updateMessage + context.wireFormat
    }
}

extension AgentUpdate: LinearEncodedTriple {
    var first: SemanticVersion { version }
    var second: Bool { isAppClip }
    var third: [ProtocolAddress] { addresses }

    init(first: SemanticVersion, second: Bool, third: [ProtocolAddress]) throws {
        self.init(version: first, isAppClip: second, addresses: third)
    }
}
