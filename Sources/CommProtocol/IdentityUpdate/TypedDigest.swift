//
//  TypedDigest.swift
//  CommProtocol
//
//  Created by Mark Xue on 7/26/24.
//

import Foundation

struct TypedDigest: DefinedWidthBinary {
    typealias Prefix = DigestTypes
    let type: DigestTypes
    let digest: Data
    
    init(
        prefix: Prefix,
        checkedData: Data
    ) throws(LinearEncodingError) {
        guard checkedData.count == prefix.contentByteSize else {
            throw.incorrectDataLength
        }
        self.type = prefix
        self.digest = checkedData
    }
    
    var wireFormat: Data { [type.rawValue] + digest }
}

enum DigestTypes: UInt8, DefinedWidthPrefix{
    case SHA256 = 1
    
    var contentByteSize: Int {
        switch self {
        case .SHA256: 32
        }
    }
}
