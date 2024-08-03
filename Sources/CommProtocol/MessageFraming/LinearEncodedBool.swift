//
//  LinearEncodedBool.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 7/31/24.
//

import Foundation

extension Bool: LinearEncodable {
    public static func parse(_ input: Data)
        throws(LinearEncodingError) -> (Bool, Int)
    {
        guard let prefix = input.first else {
            throw LinearEncodingError.unexpectedEOF
        }
        switch prefix {
        case 0: return (false, 1)
        case 1: return (true, 1)
        default: throw .unexpectedData
        }
    }

    public var wireFormat: Data {
        self ? Data([UInt8(1)]) : Data([UInt8(0)])
    }
}
