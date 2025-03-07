//
//  AnchorKey.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 3/6/25.
//

import CryptoKit
import Foundation

public struct AnchorPrivateKey: Sendable {
    private let privateKey: any PrivateSigningKey
    public let publicKey: AnchorPublicKey

    //for local storage
    public var archive: TypedKeyMaterial { .init(typedKey: privateKey) }
    public var type: SigningKeyAlgorithm {
        Swift.type(of: privateKey).signingAlgorithm
    }

    public init(algorithm: SigningKeyAlgorithm) {
        switch algorithm {
        case .curve25519:
            self.privateKey = Curve25519.Signing.PrivateKey()
            self.publicKey = .init(concrete: privateKey.publicKey)
        }
    }

    func sign(anchor: ATProtoAnchor) throws -> SignedObject<ATProtoAnchor> {
        .init(
            content: anchor,
            signature: .init(
                signingAlgorithm: type,
                signature:
                    try privateKey
                    .signature(
                        for: anchor.formatForSigning(publicKey: publicKey)
                    )
            )
        )
    }
}

public struct AnchorPublicKey: Sendable {
    let publicKey: any PublicSigningKey
    let archive: TypedKeyMaterial

    var wireFormat: Data { archive.wireFormat }

    init(concrete: any PublicSigningKey) {
        publicKey = concrete
        archive = .init(typedKey: publicKey)
    }

    func verify(signedAnchor: SignedObject<ATProtoAnchor>) throws -> ATProtoAnchor {
        let format = signedAnchor.content.formatForSigning(publicKey: self)
        guard
            publicKey.isValidSignature(
                signedAnchor.signature.signature,
                for: format
            )
        else {
            throw ProtocolError.authenticationError
        }

        return signedAnchor.content
    }
}
