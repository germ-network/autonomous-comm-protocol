//
//  DataIdentifier.swift
//  CommProtocol
//
//  Created by Mark Xue on 8/28/24.
//

///Squint and this looks like a TypedDigest. This is a defined width series of bits we use as a nonce, seed, or
///as an identifier where we would otherwise use a UUID

import CryptoKit
import Foundation

public struct DataIdentifier: DefinedWidthBinary, Sendable, Equatable, Hashable {
    public enum Widths: UInt8, DefinedWidthPrefix, Sendable, Equatable {
        case bits128 = 1
        case bits256

        public var contentByteSize: Int {
            switch self {
            case .bits128: 16
            case .bits256: 32
            }
        }

        public var keySize: SymmetricKeySize {
            switch self {
            case .bits128: .bits128
            case .bits256: .bits256
            }
        }
    }
    public typealias Prefix = Widths

    public let type: Widths
    public let identifier: Data

    public init(width: Widths) {
        self.type = width
        self.identifier = SymmetricKey(size: width.keySize).rawRepresentation
    }

    public init(
        prefix: Prefix,
        checkedData: Data
    ) throws(LinearEncodingError) {
        guard checkedData.count == prefix.contentByteSize else {
            throw .incorrectDataLength
        }
        self.type = prefix
        self.identifier = checkedData
    }

    public var wireFormat: Data { [type.rawValue] + identifier }

    init(prefix: Prefix) {
        self.type = prefix
        self.identifier = SymmetricKey(size: prefix.keySize).rawRepresentation
    }
}
