//
//  AgentHelloTests.swift
//  CommProtocol
//
//  Created by Mark Xue on 7/26/24.
//

import CryptoKit
import Foundation
import Testing

@testable import CommProtocol

struct AgentHelloTests {
    let privateKey: IdentityPrivateKey
    let coreIdentity: CoreIdentity
    let signedIdentity: SignedObject<CoreIdentity>
    let mutableFields: IdentityMutableData
    let agentKey: AgentPrivateKey
    let signedDelegation: IdentityDelegate
    let agentTBS: AgentHello.AgentTBS
    let agentHello: AgentHello

    init() throws {
        let describedImage = DescribedImage(
            imageDigest: SymmetricKey(size: .bits128).rawRepresentation,
            altText: nil
        )

        (privateKey, coreIdentity, signedIdentity) =
            try IdentityPrivateKey
            .create(
                name: UUID().uuidString,
                describedImage: describedImage)

        mutableFields = IdentityMutableData(
            counter: 2,
            pronouns: ["they/them"],
            aboutText: UUID().uuidString
        )

        (agentKey, signedDelegation) =
            try privateKey
            .createAgentDelegate(context: nil)

        agentTBS = .init(
            version: .init(major: 1, minor: 1, patch: 1),
            isAppClip: false,
            addresses: [.testMock],
            keyChoices: [:],
            imageResource: .testMock,
            expiration: .distantFuture
        )

        agentHello = try agentKey.createAgentHello(
            signedIdentity: signedIdentity,
            identityMutable:
                try privateKey
                .sign(mutableData: mutableFields),
            agentDelegate: signedDelegation,
            agentTBS: agentTBS
        )
    }

    @Test func testAgentHello() throws {
        let reencoded: AgentHello =
            try agentHello
            .encoded
            .decoded()

        let validatedHello = try reencoded.validated()

        #expect(validatedHello.coreIdentity == coreIdentity)
        #expect(validatedHello.signedIdentity.wireFormat == signedIdentity.wireFormat)
        #expect(validatedHello.agentKey == agentKey.publicKey)
        #expect(validatedHello.mutableData == validatedHello.mutableData)
        #expect(validatedHello.agentData == agentTBS)

    }

    @Test func testAgentHelloFailure() throws {
        let modifiedTBS = AgentHello.AgentTBS(
            version: agentTBS.version,
            isAppClip: true,
            addresses: agentTBS.addresses,
            keyChoices: agentTBS.keyChoices,
            imageResource: agentTBS.imageResource,
            expiration: agentTBS.expiration
        )

        let modifiedTBSHello = AgentHello(
            signedIdentity: agentHello.signedIdentity,
            identityMutable: agentHello.identityMutable,
            agentDelegate: agentHello.agentDelegate,
            agentSignedData: try modifiedTBS.encoded,
            agentSignature: agentHello.agentSignature
        )

        #expect(throws: ProtocolError.authenticationError) {
            let _ = try modifiedTBSHello.validated()
        }
    }
}

extension Resource {
    static var testMock: Self {
        .init(
            identifier: UUID().uuidString,
            plaintextDigest: SymmetricKey(size: .bits256).rawRepresentation,
            host: "example.com",
            symmetricKey: SymmetricKey(size: .bits256),
            expiration: Date.distantFuture
        )
    }
}

extension ProtocolAddress {
    static var testMock: Self {
        .init(
            identifier: UUID().uuidString,
            serviceHost: "example.com",
            expiration: Date.distantFuture
        )
    }
}
