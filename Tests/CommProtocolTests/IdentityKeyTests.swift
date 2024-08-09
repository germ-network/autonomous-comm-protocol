//
//  IdentityKeyTests.swift
//
//
//  Created by Mark @ Germ on 6/15/24.
//

import CryptoKit
import Foundation
import Testing

@testable import CommProtocol

struct IdentityKeyTests {
    let privateKey: IdentityPrivateKey
    let signedIdentity: SignedObject<CoreIdentity>

    init() throws {
        (privateKey, signedIdentity) =
            try IdentityPrivateKey
            .create(
                name: UUID().uuidString,
                describedImage: DescribedImage.mock())
    }

    @Test func testCreation() async throws {
        try print("CoreIdentity size \(signedIdentity.content.wireFormat.count)")
        try print("Signed CoreIdentity size \(signedIdentity.wireFormat.count)")

        let rehydrated: IdentityPrivateKey = try .init(archive: privateKey.archive)
        #expect(privateKey.archive == rehydrated.archive)

        let publicKey = privateKey.publicKey
        let rehydratedPublic: IdentityPublicKey = try .init(archive: publicKey.id)
        #expect(publicKey == rehydratedPublic)
    }

    @Test func testWireFormat() throws {
        let publicWireFormat = privateKey.publicKey.id.wireFormat

        let decodedPublic = try IdentityPublicKey(wireFormat: publicWireFormat)
        //can't throw within the #require
        #expect(privateKey.publicKey == decodedPublic)
    }

    @Test func testHashDomainSeparation() throws {
        let baseKey = Curve25519.Signing.PrivateKey().publicKey
        let agentKey = AgentPublicKey(concrete: baseKey)
        let identityKey = IdentityPublicKey(concrete: baseKey)

        #expect(agentKey.hashValue != identityKey.hashValue)
    }

}
