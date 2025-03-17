//
//  Integers.swift
//  CommProtocol
//
//  Created by Mark at Germ  on 9/19/24.
//

import Foundation

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
            // the UInt32 initializer will check width and make a copy
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

extension UInt64: LinearEncodable {
    public static func parse(_ input: Data) throws -> (UInt64, Int) {
        let result = try UInt64(
            dataRepresentation:
                input
                .prefix(MemoryLayout<UInt64>.size)
        )

        return (result, MemoryLayout<UInt64>.size)
    }

    public var wireFormat: Data {
        dataRepresentation
    }
}

extension UInt64 {
    public var dataRepresentation: Data {
        var endian = bigEndian
        return Data(bytes: &endian, count: MemoryLayout<UInt64>.size)
    }

    init(dataRepresentation: Data) throws(LinearEncodingError) {
        let copy = Data(dataRepresentation)  //in case a slice is passed in
        guard copy.count == MemoryLayout<UInt64>.size else {
            throw .incorrectDataLength
        }

        let bigEndian = copy.withUnsafeBytes { rawBuffer in
            rawBuffer.load(as: UInt64.self)
        }

        self = .init(bigEndian: bigEndian)
    }
}
