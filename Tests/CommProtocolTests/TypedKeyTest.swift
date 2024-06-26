//
//  TypedKeyTest.swift
//
//
//  Created by Mark @ Germ on 6/21/24.
//

import Testing
@testable import CommProtocol

import Foundation
import CryptoKit

struct TypedKeyTests {

    @Test func testSigning() async throws {
        let privateSigningKey = Curve25519.Signing.PrivateKey()
        
        let publicKey = privateSigningKey.publicKey
        let typedPublic = TypedKeyMaterial(typedKey: publicKey)
        let decodedPublic: Curve25519.Signing.PublicKey = try .init(wireFormat: typedPublic.wireFormat)
        #expect(publicKey.rawRepresentation == decodedPublic.rawRepresentation)
        
        #expect(throws: DefinedWidthError.self) {
            let _ = try Curve25519.KeyAgreement.PublicKey(wireFormat: typedPublic.wireFormat)
        }
    }
    
    @Test func testKeyAgreement() async throws {
        let privateSigningKey = Curve25519.KeyAgreement.PrivateKey()
        
        let publicKey = privateSigningKey.publicKey
        let typedPublic = TypedKeyMaterial(typedKey: publicKey)
        let decodedPublic: Curve25519.KeyAgreement.PublicKey = try .init(wireFormat: typedPublic.wireFormat)
        #expect(publicKey.rawRepresentation == decodedPublic.rawRepresentation)
        
        #expect(throws: DefinedWidthError.self) {
            let _ = try Curve25519.Signing.PublicKey(wireFormat: typedPublic.wireFormat)
        }
    }
    
    @Test func testSymmetric() async throws {
        let chaChaPolyKey = SymmetricKey(size: .bits256)
        let shortKey = SymmetricKey(size: .bits128)
        
        #expect(throws: DefinedWidthError.self) {
            let _ = try TypedKeyMaterial(algorithm: .ChaCha20Poly1305,
                                         symmetricKey: shortKey)
        }
        
        let typed = try TypedKeyMaterial(algorithm: .ChaCha20Poly1305,
                                         symmetricKey: chaChaPolyKey)
        let received = try TypedKeyMaterial(wireFormat: typed.wireFormat)
        
        #expect(received.algorithm == .ChaCha20Poly1305)
        #expect(received.keyData == chaChaPolyKey.rawRepresentation)
    }
    
    @Test func testEncapsulated() async throws {
        let senderPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let recipientPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        
        let channelInfo = Data( UUID().uuidString.utf8 )
        var hpkeSender = try HPKE.Sender(
            recipientKey: recipientPrivateKey.publicKey,
            ciphersuite: .Curve25519_SHA256_ChachaPoly,
            info: channelInfo,
            authenticatedBy: senderPrivateKey
        )
        let plaintext = UUID().uuidString
        let message = try hpkeSender.seal(Data(plaintext.utf8))
        
        let encapKey = hpkeSender.encapsulatedKey
        let wireFormat = try TypedKeyMaterial(encapAlgorithm: .HPKE_Encap_Curve25519_SHA256_ChachaPoly,
                                              data: encapKey).wireFormat
        let receivedFormat = try TypedKeyMaterial(wireFormat: wireFormat)
        #expect(receivedFormat.algorithm == .HPKE_Encap_Curve25519_SHA256_ChachaPoly)
        let receivedKey = receivedFormat.keyData
        
        var hpkeReceiver = try HPKE.Recipient(
            privateKey: recipientPrivateKey,
            ciphersuite: .Curve25519_SHA256_ChachaPoly,
            info: channelInfo,
            encapsulatedKey: receivedKey,
            authenticatedBy: senderPrivateKey.publicKey
        )
        
        let decrypted = try hpkeReceiver.open(message)
        #expect(decrypted == Data(plaintext.utf8))
    }

}


