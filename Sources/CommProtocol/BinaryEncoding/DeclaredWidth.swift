//
//  DeclaredWidth.swift
//  CommProtocol
//
//  Created by Mark Xue on 7/27/24.
//

import Foundation

extension UInt32 {
    var dataRepresentation: Data {
        var endian = bigEndian
        return Data(bytes: &endian, count: MemoryLayout<UInt32>.size)
    }
    
    init(dataRepresentation: Data) throws {
        guard dataRepresentation.count == MemoryLayout<UInt32>.size else {
            throw DefinedWidthError.incorrectDataLength
        }
        
        let bigEndian = dataRepresentation.withUnsafeBytes { rawBuffer in
            rawBuffer.load(as: UInt32.self)
        }
        
        self = .init(bigEndian: bigEndian)
    }
}

extension Data {
    init(declaredWidthWire: Data) throws {
        guard declaredWidthWire.count > MemoryLayout<UInt32>.size else {
            throw DefinedWidthError.incorrectDataLength
        }
        
        let prefix = Data(declaredWidthWire.prefix(MemoryLayout<UInt32>.size ))
        let expectedWidth = try Int(UInt32(dataRepresentation: prefix)) + MemoryLayout<UInt32>.size
        guard declaredWidthWire.count == expectedWidth else {
            throw DefinedWidthError.incorrectDataLength
        }
        self.init(declaredWidthWire.suffix(from: MemoryLayout<UInt32>.size))
    }
    
    var declaredWidthWire: Data {
        get throws {
            guard count <= UInt32.max, count >= UInt32.min else {
                throw DefinedWidthError.incorrectDataLength
            }
            let count32 = UInt32(count)
            return count32.dataRepresentation + self
        }
    }
}
