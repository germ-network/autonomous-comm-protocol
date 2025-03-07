//
//  MockAnchor.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 3/6/25.
//

import CryptoKit
import Foundation

extension ATProtoAnchor {
    static public func signedMock() throws -> (AnchorPrivateKey, SignedObject<ATProtoAnchor>) {
        let anchorPrivateKey = AnchorPrivateKey(algorithm: .curve25519)

        let signedObject = try anchorPrivateKey.sign(anchor: .mock())

        return (anchorPrivateKey, signedObject)
    }
}

extension ATProtoAnchor {
    static public func mock() -> ATProtoAnchor {
        //ATProto did is hash-bashed, so likely is a digest encoding
        .init(
            did: SymmetricKey(size: .bits256).rawRepresentation
                .base64URLEncodedString(),
            handle: UUID().uuidString,
            previousDigest: nil
        )
    }
}
