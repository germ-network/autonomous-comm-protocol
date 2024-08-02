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
            OptionalString.self,
            input: input
        )

        let result = SemanticVersion(
            major: major,
            minor: minor,
            patch: patch,
            preReleaseSuffix: suffix.string
        )
        return (result, consumed)
    }

    public var wireFormat: Data {
        get throws {
            try major.wireFormat
                + minor.wireFormat
                + patch.wireFormat
                + OptionalString(preReleaseSuffix).wireFormat
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
                dataRepresentation:
                    input
                    .suffix(from: input.startIndex + 1)
                    .prefix(MemoryLayout<UInt32>.size)
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
