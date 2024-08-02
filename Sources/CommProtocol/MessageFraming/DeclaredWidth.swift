//
//  DeclaredWidth.swift
//  CommProtocol
//
//  Created by Mark Xue on 7/27/24.
//

import Foundation

extension UInt16 {
    var dataRepresentation: Data {
        var endian = bigEndian
        return Data(bytes: &endian, count: MemoryLayout<UInt16>.size)
    }

    init(dataRepresentation: Data) throws(LinearEncodingError) {
        guard dataRepresentation.count == MemoryLayout<UInt16>.size else {
            throw .incorrectDataLength
        }

        let copy = Data(dataRepresentation)

        let bigEndian = copy.withUnsafeBytes { rawBuffer in
            rawBuffer.load(as: UInt16.self)
        }

        self = .init(bigEndian: bigEndian)
    }
}

extension UInt16: LinearEncodable {
    static public func parse(_ input: Data) throws -> (UInt16, Int) {
        let prefix = input.prefix(MemoryLayout<UInt16>.size)
        let counter = try UInt16(dataRepresentation: prefix)

        return (counter, MemoryLayout<UInt16>.size)
    }

    public var wireFormat: Data {
        dataRepresentation
    }
}

struct DeclaredWidthData: Sendable, Equatable {
    let width: UInt16
    let body: Data

    init(body: Data) throws(LinearEncodingError) {
        guard !body.isEmpty else {
            throw .incorrectDataLength
        }
        guard body.count <= UInt16.max else {
            throw .bodyTooLarge
        }
        self.width = UInt16(body.count)
        self.body = body
    }

    var wireFormat: Data {
        width.dataRepresentation + body
    }
}

extension DeclaredWidthData: LinearEncodable {
    static func parse(_ input: Data)
        throws(LinearEncodingError) -> (DeclaredWidthData, Int)
    {
        let prefix = input.prefix(MemoryLayout<UInt16>.size)
        let bodyWidth = try Int(UInt16(dataRepresentation: prefix))
        let consumeWidth = bodyWidth + MemoryLayout<UInt16>.size
        guard input.count >= consumeWidth else {
            throw .unexpectedEOF
        }

        let bodySlice =
            input
            .suffix(from: input.startIndex + MemoryLayout<UInt16>.size)

        let result = try DeclaredWidthData(
            body: bodySlice.prefix(bodyWidth)
        )
        return (result, consumeWidth)
    }
}

struct DeclaredWidthOptionalData {
    let width: UInt16
    let body: Data?

    init(body: Data?) throws(LinearEncodingError) {
        guard let body, body.count != 0 else {
            self.width = 0
            self.body = nil
            return
        }

        guard body.count <= UInt16.max else {
            throw .bodyTooLarge
        }
        self.width = UInt16(body.count)
        self.body = body
    }

    var wireFormat: Data {
        width.dataRepresentation + (body ?? Data())
    }
}

extension DeclaredWidthOptionalData: LinearEncodable {
    static func parse(_ input: Data)
        throws(LinearEncodingError) -> (DeclaredWidthOptionalData, Int)
    {
        let prefix = input.prefix(MemoryLayout<UInt16>.size)
        let bodyWidth = try Int(UInt16(dataRepresentation: prefix))
        let consumeWidth = bodyWidth + MemoryLayout<UInt16>.size
        guard input.count >= consumeWidth else {
            throw .unexpectedEOF
        }

        guard bodyWidth != 0 else {
            return (try .init(body: nil), consumeWidth)
        }

        let bodySlice =
            input
            .suffix(from: input.startIndex + MemoryLayout<UInt16>.size)

        let result = try DeclaredWidthOptionalData(
            body: bodySlice.prefix(bodyWidth)
        )
        return (result, consumeWidth)
    }
}
