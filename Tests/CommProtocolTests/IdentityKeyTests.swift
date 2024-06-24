//
//  IdentityKeyTests.swift
//
//
//  Created by Mark @ Germ on 6/15/24.
//

import Foundation
import Testing
@testable import CommProtocol
import CryptoKit

struct IdentityKeyTests {
    let privateKey: IdentityPrivateKey
    let coreIdentity: CoreIdentity
    let signedIdentity: SignedIdentity
    
    init() throws {
        let describedImage = DescribedImage(
            imageDigest: SymmetricKey(size: .bits128).rawRepresentation,
            altText: nil
        )
        
        (privateKey, coreIdentity, signedIdentity) = try IdentityPrivateKey
            .create(name: UUID().uuidString,
                    describedImage: describedImage)
    }
    
    @Test func testCreation() async throws {
        let encoded = try privateKey.encoded
        let decoded: IdentityPrivateKey = try encoded.decoded()
        #expect(privateKey.publicKey.id == decoded.publicKey.id )
        
        let publicKey = privateKey.publicKey
        let encodedPublicKey = try publicKey.encoded
        let decodedPublicKey: IdentityPublicKey = try encodedPublicKey.decoded()
        #expect(publicKey.id == decodedPublicKey.id)
    }
    
    @Test func testWireFormat() throws {
        let publicWireFormat = try privateKey.publicKey.wireFormat
        
        let decodedPublic = try IdentityPublicKey(wireFormat: publicWireFormat)
        //can't throw within the #require
        #expect(privateKey.publicKey == decodedPublic)
    }
}

