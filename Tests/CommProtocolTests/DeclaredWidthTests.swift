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
        let value = UInt16.random(in: UInt16.min...UInt16.max)
        let reencoded = try UInt16(dataRepresentation: value.dataRepresentation)
        #expect(value == reencoded)
        
        let prefix = Data(value.dataRepresentation.prefix(1))
        #expect(throws: LinearEncodingError.incorrectDataLength) {
            let _ = try UInt16(dataRepresentation: prefix)
        }
    }
    
    @Test func testDeclaredWidth() throws {
        let width = UInt8.random(in: 1...UInt8.max)
        let data = SymmetricKey(size: .init(bitCount: Int(width) * 8)).dataRepresentation
        
        let encoded = try data.declaredWidthWire
        #expect(encoded.count == data.count + MemoryLayout<UInt16>.size)
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
