//
//  TypedDigest.swift
//  CommProtocol
//
//  Created by Mark Xue on 7/26/24.
//

import CryptoKit
import Foundation

public struct TypedDigest: DefinedWidthBinary, Sendable, Equatable {
    public typealias Prefix = DigestTypes
    let type: DigestTypes
    let digest: Data

    public init(
        prefix: Prefix,
        checkedData: Data
    ) throws(LinearEncodingError) {
        guard checkedData.count == prefix.contentByteSize else {
            throw .incorrectDataLength
        }
        self.type = prefix
        self.digest = checkedData
    }

    public var wireFormat: Data { [type.rawValue] + digest }

    init(prefix: Prefix, over body: Data) {
        self.type = prefix
        switch prefix {
        case .sha256:
            self.digest = SHA256.hash(data: body).data
        }
    }
}

public enum DigestTypes: UInt8, DefinedWidthPrefix, Sendable, Equatable {
    case sha256 = 1

    public var contentByteSize: Int {
        switch self {
        case .sha256: 32
        }
    }
}
