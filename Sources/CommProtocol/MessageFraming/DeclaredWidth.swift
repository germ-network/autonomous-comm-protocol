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

extension Data {
    init(declaredWidthWire: Data) throws(LinearEncodingError) {
        guard declaredWidthWire.count > MemoryLayout<UInt16>.size else {
            throw .incorrectDataLength
        }
        
        let prefix = Data(declaredWidthWire.prefix(MemoryLayout<UInt16>.size ))
        let expectedWidth = try Int(UInt16(dataRepresentation: prefix)) + MemoryLayout<UInt16>.size
        guard declaredWidthWire.count == expectedWidth else {
            throw .incorrectDataLength
        }
        self.init(declaredWidthWire.suffix(from: MemoryLayout<UInt16>.size))
    }
    
    var declaredWidthWire: Data {
        get throws(LinearEncodingError) {
            guard count <= UInt16.max, count >= UInt16.min else {
                throw .incorrectDataLength
            }
            let count16 = UInt16(count)
            return count16.dataRepresentation + self
        }
    }
}
