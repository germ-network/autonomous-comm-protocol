//
//  Mocks.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 7/30/24.
//

import Foundation
import CryptoKit
@testable import CommProtocol

extension AgentUpdate {
    static func mock() -> Self {
        .init(
            version: .init(major: 1, minor: 1, patch: 1),
            isAppClip: true,
            addresses: [.mock(), .mock()],
            imageResource: .mock(),
            expiration: .distantFuture
        )
    }
}

extension ProtocolAddress {
    static func mock() -> Self {
        .init(identifier: UUID().uuidString,
              serviceHost: UUID().uuidString,
              expiration: .distantFuture)
    }
}

struct Mocks {
    static func mockMessage() -> Data {
        SymmetricKey(size: .bits256).rawRepresentation
    }
}

extension Resource {
    static func mock() -> Self {
        .init(
            identifier: UUID().uuidString,
            plaintextDigest: SymmetricKey(size: .bits256).rawRepresentation,
            host: "example.com",
            symmetricKey: SymmetricKey(size: .bits256),
            expiration: Date.distantFuture
        )
    }
}

extension TypedDigest {
    static func mock() throws -> Self {
        try .init(
            prefix: .sha256,
            checkedData: SymmetricKey(size: .bits256).rawRepresentation
        )
    }
}

public extension DescribedImage {
    static func mock() throws -> Self {
        .init(
            imageDigest: SymmetricKey(size: .bits256).rawRepresentation,
            altText: "description"
        )
    }
}
