//
//  LinearEncodedData.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 7/31/24.
//

import Foundation

///Most of our binary objects are of defined length, so we mainly use this for a utf8 encoded Strings
///So as not to conflict with the generic conformance for Optional: LinearEncodable, we
///use a wrapper structure
///First byte encoding 0 if none, short suffix, overflow at 255 into a full DefinedBinary
///

struct OptionalData: LinearEncodable {
    static let none: Self = .init(data: nil)
    let data: Data?

    static func parse(_ input: Data) throws(LinearEncodingError) -> (OptionalData, Int) {
        guard let prefix = input.first else {
            throw .unexpectedEOF
        }
        let slice = input.suffix(from: input.startIndex + 1)
        switch prefix {
        case 0: return (.none, 1)
        case UInt8.max:
            let (wideData, consumed) = try DeclaredWidthData.parse(slice)
            let result = wideData.body
            return (.init(data: result), consumed + 1)
        default:
            guard input.count > prefix else {
                throw .unexpectedEOF
            }
            let width = Int(UInt8(prefix))
            let data = slice.prefix(width)
            return (.init(data: data), width + 1)
        }
    }

    var wireFormat: Data {
        get throws {
            guard let data else {
                return .init([UInt8(0)])
            }
            if data.count < UInt8.max {
                return [UInt8(data.count)] + data
            } else {
                let wideEncoded = try DeclaredWidthData(body: data)
                return [UInt8.max] + wideEncoded.wireFormat
            }
        }
    }
}

struct OptionalString: LinearEncodable {
    let string: String?

    init(_ string: String?) {
        self.string = string
    }

    var optionalData: OptionalData {
        .init(data: string?.utf8Data)
    }

    init(optionalData: OptionalData) {
        self.string = optionalData.data?.utf8String
    }

    static func parse(_ input: Data) throws -> (OptionalString, Int) {
        let (data, consumed) = try OptionalData.parse(input)
        return (.init(optionalData: data), consumed)
    }

    var wireFormat: Data {
        get throws {
            try optionalData.wireFormat
        }
    }
}

extension String: LinearEncodable {
    static public func parse(_ input: Data) throws -> (String, Int) {
        let (maybe, consumed) = try OptionalString.parse(input)
        guard let string = maybe.string else {
            throw LinearEncodingError.requiredValueMissing
        }
        return (string, consumed)
    }

    public var wireFormat: Data {
        get throws {
            try OptionalString(self).wireFormat
        }
    }
}

extension Data: LinearEncodable {
    static public func parse(_ input: Data) throws -> (Data, Int) {
        let (maybe, consumed) = try OptionalData.parse(input)
        guard let data = maybe.data else {
            throw LinearEncodingError.requiredValueMissing
        }
        return (data, consumed)
    }

    public var wireFormat: Data {
        get throws {
            try OptionalData(data: self).wireFormat
        }
    }
}
