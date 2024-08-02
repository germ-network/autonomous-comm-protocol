//
//  Mocks.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 7/30/24.
//

import CryptoKit
import Foundation

@testable import CommProtocol

extension AgentUpdate {
    static func mock() -> Self {
        .init(
            version: .init(major: 1, minor: 1, patch: 1),
            isAppClip: true,
            addresses: [.mock()],
            imageResource: .mock()
        )
    }
}

extension ProtocolAddress {
    static func mock() -> Self {
        .init(
            identifier: UUID().uuidString,
            serviceHost: UUID().uuidString,
            expiration: .distantFuture
        )
    }
}

struct Mocks {
    static func mockMessage() -> Data {
        SymmetricKey(size: .bits256).rawRepresentation
    }

    static func mockIdentity() throws -> (
        IdentityPrivateKey,
        CoreIdentity,
        SignedObject<CoreIdentity>
    ) {
        try IdentityPrivateKey.create(
            name: UUID().uuidString,
            describedImage: try .mock()
        )
    }
}

extension Resource {
    static func mock() -> Self {
        .init(
            identifier: UUID().uuidString,
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

extension DescribedImage {
    public static func mock() throws -> Self {
        .init(
            imageDigest: try .mock(),
            altText: "description"
        )
    }
}

extension CoreIdentity {
    public static func mock(newIdentity: IdentityPublicKey) throws -> Self {
        try .init(
            id: newIdentity,
            name: UUID().uuidString,
            describedImage: try .mock(),
            version: CoreIdentity.Constants.currentVersion,
            nonce: SymmetricKey(size: .bits128).rawRepresentation
        )
    }
}

extension SemanticVersion {
    public static func mock() -> Self {
        let suffix = Bool.random() ? nil : UUID().uuidString

        return .init(
            major: UInt32.random(in: UInt32.min...UInt32.max),
            minor: UInt32.random(in: UInt32.min...UInt32.max),
            patch: UInt32.random(in: UInt32.min...UInt32.max),
            preReleaseSuffix: suffix
        )
    }
}

extension IdentityMutableData {
    public static func mock() -> Self {
        .init(
            counter: UInt16.random(in: 0...(.max)),
            pronouns: [TestPronouns.random().rawValue, TestPronouns.random().rawValue],
            aboutText: nil
        )
    }
}

enum TestPronouns: String, CaseIterable {
    case he = "he/him"
    case she = "she/her"
    case they = "they/them"

    static func random() -> Self {
        switch UInt8.random(in: 0...2) {
        case 0: .he
        case 1: .she
        default: .they
        }
    }
}

extension AgentHello.NewAgentData {
    static func mock() -> Self {
        .init(
            version: .init(major: 1, minor: 1, patch: 1),
            isAppClip: false,
            addresses: [.mock()],
            keyChoices: [
                .init(
                    suite: .mlsCurve25519ChaChaPoly,
                    keyPackage: Mocks.mockMessage()
                )
            ],
            imageResource: .mock(),
            expiration: .distantFuture
        )
    }
}
