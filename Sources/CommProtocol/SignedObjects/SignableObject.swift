//
//  SignableObject.swift
//
//
//  Created by Mark @ Germ on 6/16/24.
//

import CryptoKit
import Foundation

public struct SignedObject<Content: LinearEncodable>: Sendable {
    public let content: Content
    let signature: TypedSignature
}

extension SignedObject: LinearEncodable {
    public static func parse(_ input: Data) throws -> (
        SignedObject<Content>,
        Int
    ) {
        let (content, signature, consumed) = try LinearEncoder.decode(
            Content.self,
            TypedSignature.self,
            input: input
        )
        return (
            .init(content: content, signature: signature),
            consumed
        )
    }

    public var wireFormat: Data {
        get throws {
            try content.wireFormat + signature.wireFormat
        }
    }
}

//like TypedKeyMaterial, prepend a byte that indicates length of the body
public struct TypedSignature: DefinedWidthBinary, Sendable {
    public typealias Prefix = SigningKeyAlgorithm
    let signingAlgorithm: SigningKeyAlgorithm
    let signature: Data

    public var wireFormat: Data {
        [signingAlgorithm.rawValue] + signature
    }

    public init(prefix: SigningKeyAlgorithm, checkedData: Data) throws(LinearEncodingError) {
        guard prefix.contentByteSize == checkedData.count else {
            throw .incorrectDataLength
        }
        self.init(signingAlgorithm: prefix, signature: checkedData)
    }

    init(signingAlgorithm: SigningKeyAlgorithm, signature: Data) {
        self.signingAlgorithm = signingAlgorithm
        self.signature = signature
    }
}
