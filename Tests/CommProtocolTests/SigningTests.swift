//
//  SigningTests.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 2/26/25.
//

import CommProtocol
import CryptoKit
import Testing

struct SigningTests {
    let privateKey = AgentPrivateKey(algorithm: .curve25519)

    @Test func testRejoin() async throws {
        let rejoin = ReJoin.mock()

        let signed = try privateKey.sign(reJoin: rejoin)

        let verified = try signed.verified(for: privateKey.publicKey)
        #expect(verified.keyPackageMessage == rejoin.keyPackageMessage)
        #expect(verified.groupId == rejoin.groupId)
    }

}
