//
//  SemanticVersion.swift
//
//
//  Created by Mark @ Germ on 8/4/23.
//

import Foundation

public struct SemanticVersion: Equatable, Hashable, Sendable {
    let major: UInt32
    let minor: UInt32
    let patch: UInt32
    let preReleaseSuffix: String?

    public init(
        major: UInt32,
        minor: UInt32,
        patch: UInt32,
        preReleaseSuffix: String? = nil
    ) {
        self.major = major
        self.minor = minor
        self.patch = patch
        self.preReleaseSuffix = preReleaseSuffix
    }

    public var string: String {
        "\(major).\(minor).\(patch)" + (preReleaseSuffix ?? "")
    }
}

///Compactly represent this as 3 UInt8 bytes and a 4th enum indicating if there is a suffix
///Overflow the UInt8 to Uint32
extension SemanticVersion: LinearEncodable {
    public static func parse(_ input: Data) throws -> (SemanticVersion, Int) {
        let (major, minor, patch, suffix, consumed) = try LinearEncoder.decode(
            UInt32.self,
            UInt32.self,
            UInt32.self,
            (String?).self,
            input: input
        )

        let result = SemanticVersion(
            major: major,
            minor: minor,
            patch: patch,
            preReleaseSuffix: suffix
        )
        return (result, consumed)
    }

    public var wireFormat: Data {
        get throws {
            try major.wireFormat
                + minor.wireFormat
                + patch.wireFormat
                + preReleaseSuffix.wireFormat
        }
    }

}

///Compactly represent as a UInt8 if possible, overflowing at Uint8.max to 4 + 1 bytes
extension UInt32: LinearEncodable {
    public static func parse(_ input: Data)
        throws(LinearEncodingError) -> (UInt32, Int)
    {
        guard let prefix = input.first else {
            throw .unexpectedEOF
        }
        if prefix < UInt8.max {
            return (.init(prefix), 1)
        } else {
            let result = try UInt32(
                dataRepresentation: input.suffix(from: input.startIndex + 1)
            )

            return (result, 1 + MemoryLayout<UInt32>.size)
        }
    }

    public var wireFormat: Data {
        if self < UInt8.max {
            .init([UInt8(self)])
        } else {
            [UInt8.max] + dataRepresentation
        }
    }

}

//First byte encoding 0 if none, short suffix, overflow at 255 into a full DefinedBinary
extension String?: LinearEncodable {
    public static func parse(_ input: Data)
        throws(LinearEncodingError) -> (String?, Int)
    {
        guard let prefix = input.first else {
            throw .unexpectedEOF
        }
        let slice = input.suffix(from: input.startIndex + 1)
        switch prefix {
        case 0: return (nil, 1)
        case UInt8.max:
            let (wideData, consumed) = try DeclaredWidthData.parse(slice)
            let result = wideData.body.utf8String
            return (result, consumed + 1)
        default:
            guard input.count > prefix else {
                throw .unexpectedEOF
            }
            let width = Int(UInt8(prefix))
            let string = slice.prefix(width).utf8String
            return (string, width + 1)
        }
    }

    public var wireFormat: Data {
        get throws {
            guard let self else {
                return .init([UInt8(0)])
            }
            let encoded = self.utf8Data
            if encoded.count < UInt8.max {
                return [UInt8(encoded.count)] + encoded
            } else {
                let wideEncoded = try DeclaredWidthData(body: encoded)
                return [UInt8.max] + wideEncoded.wireFormat
            }
        }
    }
}

extension String {
    public var wireFormat: Data {
        get throws {
            try (self as String?).wireFormat
        }
    }
}

extension UInt32 {
    var dataRepresentation: Data {
        var endian = bigEndian
        return Data(bytes: &endian, count: MemoryLayout<UInt32>.size)
    }

    init(dataRepresentation: Data) throws(LinearEncodingError) {
        let copy = Data(dataRepresentation)  //in case a slice is passed in
        guard copy.count == MemoryLayout<UInt32>.size else {
            throw .incorrectDataLength
        }

        let bigEndian = copy.withUnsafeBytes { rawBuffer in
            rawBuffer.load(as: UInt32.self)
        }

        self = .init(bigEndian: bigEndian)
    }
}

//TODO: remove
extension SemanticVersion: Codable {}
