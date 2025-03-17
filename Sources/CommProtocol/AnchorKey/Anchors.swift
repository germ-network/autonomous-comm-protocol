//
//  Anchors.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 3/6/25.
//

import CryptoKit
import Foundation

public struct ATProtoAnchor: Equatable {
    public let did: String
    public let handle: String
    public let previousDigest: Data?

    func formatForSigning(anchorKey: AnchorPublicKey) -> Data {
        Data(("anchor" + did + "." + handle).utf8)
            + anchorKey
            .wireFormat + (previousDigest ?? .init())
    }
}

extension ATProtoAnchor: LinearEncodedTriple {
    public var first: String { did }
    public var second: String { handle }
    public var third: Data? { previousDigest }

    public init(first: String, second: String, third: Data?) throws {
        self.init(did: first, handle: second, previousDigest: third)
    }
}
