//
//  TypedDigest.swift
//  CommProtocol
//
//  Created by Mark Xue on 7/26/24.
//

import Foundation

public struct TypedDigest: DefinedWidthBinary {
    public typealias Prefix = DigestTypes
    let type: DigestTypes
    let digest: Data
    
    public init(
        prefix: Prefix,
        checkedData: Data
    ) throws(LinearEncodingError) {
        guard checkedData.count == prefix.contentByteSize else {
            throw.incorrectDataLength
        }
        self.type = prefix
        self.digest = checkedData
    }
    
    public var wireFormat: Data { [type.rawValue] + digest }
}

public enum DigestTypes: UInt8, DefinedWidthPrefix{
    case SHA256 = 1
    
    public var contentByteSize: Int {
        switch self {
        case .SHA256: 32
        }
    }
}
