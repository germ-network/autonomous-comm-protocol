//
//  CryptoKit+ExtensionsTests.swift
//
//
//  Created by Mark Xue on 6/13/24.
//

import Testing
@testable import CommProtocol
import CryptoKit

struct CryptoKitExtensionTests {
    @Test func testKeyAgreementCoding() throws {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey
        
        let privateEncoded = try privateKey.encoded
        let decodedPrivate: Curve25519.KeyAgreement.PrivateKey = try privateEncoded
            .decoded()
        #expect(decodedPrivate.rawRepresentation == privateKey.rawRepresentation)
        
        let publicEncoded = try publicKey.encoded
        let decodedPublic: Curve25519.KeyAgreement.PublicKey = try publicEncoded
            .decoded()
        #expect(publicKey.rawRepresentation == decodedPublic.rawRepresentation)
        
    }
    
    @Test func testSigningKeyCoding() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        
        let privateEncoded = try privateKey.encoded
        let decodedPrivate: Curve25519.Signing.PrivateKey = try privateEncoded
            .decoded()
        #expect(decodedPrivate.rawRepresentation == privateKey.rawRepresentation)
        
        let publicEncoded = try publicKey.encoded
        let decodedPublic: Curve25519.Signing.PublicKey = try publicEncoded
            .decoded()
        #expect(publicKey == decodedPublic)
    }
}
