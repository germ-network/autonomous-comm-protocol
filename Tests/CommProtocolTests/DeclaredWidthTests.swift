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
        let body = SymmetricKey(size: .init(bitCount: Int(width) * 8)).dataRepresentation
        
        let encoded = try DeclaredWidthData(body: body)
        #expect(encoded.width == width)
        let wireFormat = encoded.wireFormat
        #expect(wireFormat.count == Int(width) + MemoryLayout<UInt16>.size)
        let decoded = try DeclaredWidthData.finalParse(wireFormat)
        
        #expect(body == decoded.body)
        
        //fail the prefix check
        #expect(throws: LinearEncodingError.incorrectDataLength) {
            let _ = try DeclaredWidthData.finalParse( wireFormat.prefix(1) )
        }
        
        //fail the expected width check
        #expect(throws: LinearEncodingError.unexpectedEOF) {
            let _ = try DeclaredWidthData.finalParse( wireFormat.prefix(wireFormat.count - 1) )
        }
    }
}
