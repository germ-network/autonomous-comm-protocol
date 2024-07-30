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
        
        let bigEndian = dataRepresentation.withUnsafeBytes { rawBuffer in
            rawBuffer.load(as: UInt16.self)
        }
        
        self = .init(bigEndian: bigEndian)
    }
}

struct DeclaredWidthData {
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
    static func parse(_ input: Data) throws(LinearEncodingError) -> (DeclaredWidthData, Int) {
        let prefix =  input.prefix( MemoryLayout<UInt16>.size )
        let bodyWidth = try Int ( UInt16(dataRepresentation: prefix))
        let consumeWidth = bodyWidth + MemoryLayout<UInt16>.size
        guard input.count >= consumeWidth else {
            throw .unexpectedEOF
        }
        
        let bodySlice = input
            .suffix(from: input.startIndex + MemoryLayout<UInt16>.size )
        
        let result = try DeclaredWidthData(
            body: bodySlice.prefix(bodyWidth)
        )
        return (result, consumeWidth)
    }
}
