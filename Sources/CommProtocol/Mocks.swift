//
//  Mocks.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 7/30/24.
//

import CryptoKit
import Foundation

extension AgentUpdate {
    public static func mock() -> Self {
        .init(
            version: .mock(),
            isAppClip: true,
            addresses: [.mock()]
        )
    }
}

extension ProtocolAddress {
    public static func mock() -> Self {
        .init(
            identifier: UUID().uuidString,
            serviceHost: UUID().uuidString,
            expiration: .distantFuture
        )
    }
}

public struct Mocks {
    public static func mockMessage() -> Data {
        SymmetricKey(size: .bits256).rawRepresentation
    }

    public static func mockIdentity() throws -> (
        IdentityPrivateKey,
        SignedObject<CoreIdentity>
    ) {
        try IdentityPrivateKey.create(
            name: UUID().uuidString,
            describedImage: try .mock()
        )
    }
}

extension Resource {
    public static func mock() -> Self {
        .init(
            identifier: UUID().uuidString,
            host: "example.com",
            symmetricKey: SymmetricKey(size: .bits256),
            expiration: Date.distantFuture
        )
    }
}

extension TypedDigest {
    public static func mock() throws -> Self {
        try .init(
            prefix: .sha256,
            checkedData: SymmetricKey(size: .bits256).rawRepresentation
        )
    }
}

extension DescribedImage {
    public static func mock() throws -> Self {
        .init(
            imageData: SymmetricKey(size: .bits256).rawRepresentation,
            altText: "description")
    }
}

//extension CoreIdentity {
//    public static func mock(newIdentity: IdentityPublicKey) throws -> Self {
//        //use the API to do so instead of internal methods
//        let (_, identity, _) = try IdentityPrivateKey.create(
//            name: UUID().uuidString,
//            describedImage: try .mock()
//        )
//
//        return identity
//    }
//}

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
            aboutText: nil,
            imageResource: .mock()
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

extension MLSIntroduction {
    public static func mock() -> Self {
        .init(
            suite: .mlsCurve25519ChaChaPoly,
            kemPublicKeyData: SymmetricKey(size: .bits256).rawRepresentation,
            encodedKeyPackage: Mocks.mockMessage()
        )
    }
}

extension AgentHello.NewAgentData {
    public static func mock() -> Self {
        .init(
            agentUpdate: .mock(),
            keyChoices: [.mock()],
            expiration: .distantFuture
        )
    }
}
