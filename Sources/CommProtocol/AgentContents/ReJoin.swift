//
//  ReJoin.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 2/26/25.
//

import Foundation

//Our MLS implementation has a concept of a rejoin with a KeyPackage
//In TwoMLS we bind the reconstructed group to expored secrets from
//the last known good epochs.
//But we still want to ensure the credential binds to the KeyPackage, so we
//issue an app-level message where the agent signs over the

public struct ReJoin {
    public let keyPackageMessage: Data
    public let groupId: Data //groupId of the send group the ReJoin is issued on
    
    func formatForSigning() throws -> Data {
        try "rejoin".utf8Data + wireFormat
    }
}

extension ReJoin: LinearEncodedPair {
    public var first: Data { keyPackageMessage }
    public var second: Data { groupId }
    
    public init(first: Data, second: Data) throws {
        self.init(keyPackageMessage: first, groupId: second)
    }
}

extension SignedObject<ReJoin> {
    public func verified(for publicKey: AgentPublicKey) throws -> ReJoin {
        guard signature.signingAlgorithm == Swift
            .type(of: publicKey.publicKey).signingAlgorithm else {
            throw ProtocolError.suiteMismatch
        }
        guard publicKey.publicKey.isValidSignature(
            signature.signature,
            for: try content.formatForSigning()
        ) else {
            throw ProtocolError.authenticationError
        }
        return content
    }
}
