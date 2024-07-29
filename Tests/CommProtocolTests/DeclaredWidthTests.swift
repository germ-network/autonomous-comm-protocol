//
//  DeclaredWidthTests.swift
//  CommProtocol
//
//  Created by Mark Xue on 7/27/24.
//

import Foundation
import Testing
import CryptoKit
@testable import CommProtocol

struct DeclaredWidthTests {
    @Test func testUIntConversion() throws {
        let value = UInt32.random(in: UInt32.min...UInt32.max)
        let reencoded = try UInt32(dataRepresentation: value.dataRepresentation)
        #expect(value == reencoded)
        
        let prefix = Data(value.dataRepresentation.prefix(3))
        #expect(throws: LinearEncodingError.incorrectDataLength) {
            let _ = try UInt32(dataRepresentation: prefix)
        }
    }
    
    @Test func testDeclaredWidth() throws {
        let width = UInt8.random(in: UInt8.min...UInt8.max)
        let data = SymmetricKey(size: .init(bitCount: Int(width) * 8)).dataRepresentation
        
        let encoded = try data.declaredWidthWire
        #expect(encoded.count == data.count + MemoryLayout<UInt32>.size)
        let decoded = try Data(declaredWidthWire: encoded)
        
        #expect(data == decoded)
        
        #expect(throws: LinearEncodingError.incorrectDataLength) {
            let _ = try Data(
                declaredWidthWire:  Data(encoded.prefix(3))
            )
        }
        
        #expect(throws: LinearEncodingError.incorrectDataLength) {
            let _ = try Data(
                declaredWidthWire: Data(encoded.prefix(encoded.count - 1))
            )
        }
    }
}
