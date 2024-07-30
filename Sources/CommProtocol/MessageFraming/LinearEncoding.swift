//
//  LinearEncoding.swift
//  CommProtocol
//
//  Created by Mark Xue on 7/28/24.
//

import Foundation

///A format for consuming a stream of binary data into a known structure, with some branch points

public protocol LinearEncoding  {
    static func parse(_ input: Data) throws -> (Self, Int)
    var wireFormat: Data { get throws }
}

public extension LinearEncoding {
    static func continuingParse(_ input: Data) throws -> (Self, Data) {
        let (result, remainder) = try optionalParse(input)
        guard let remainder else { throw LinearEncodingError.unexpectedEOF }
        return (result, remainder)
    }
    
    static func finalParse(_ input: Data) throws -> Self {
        let (result, remainder) = try optionalParse(input)
        guard remainder == nil else { throw LinearEncodingError.unexpectedData }
        return result
    }
    
    static func optionalParse(_ input: Data) throws -> (Self, Data?) {
        let (result, consumed) = try parse(input)
        guard input.count > consumed else { return (result, nil) }
        return (result, input.suffix(from: input.startIndex + consumed )) 
    }
}

public struct LinearEncoder {
    static func decode<T: LinearEncoding, U:LinearEncoding>(
        _ firstType: T.Type,
        _ secondType: U.Type,
        input: Data
    ) throws -> (T, U, Data) {
        let (first, firstRemainder) = try T.continuingParse(input)
        
        let (second, secondRemainder) = try U.continuingParse(firstRemainder)
        return (first, second, secondRemainder)
    }
}

public enum LinearEncodingError: Error, Equatable {
    case mismatchedAlgorithms(expected: TypedKeyMaterial.Algorithms,
                              found: TypedKeyMaterial.Algorithms)
    case unknownTypedKeyAlgorithm(UInt8)
    case invalidTypedKey
    case invalidTypedSignature
    case invalidPrefix
    case incorrectDataLength
    case unexpectedData
    case unexpectedEOF
    case notImplemented //shim
}

extension LinearEncodingError: LocalizedError {
    public var errorDescription: String? {
        switch self{
        case .mismatchedAlgorithms(let expected, let found):
            "Mismatched key algorithm, expected \(expected), found \(found)"
        case .unknownTypedKeyAlgorithm(let index):
            "Unknown Typed Key Algorithm \(index)"
        case .invalidTypedKey: "Invalid typed key"
        case .invalidTypedSignature: "Invalid typed signature"
        case .invalidPrefix: "Invalid prefix"
        case .incorrectDataLength: "Incorrect Data Length"
        case .unexpectedData: "E"
        case .unexpectedEOF: "Unexpected end of input"
        case .notImplemented: "Not Implemented"
        }
    }
}

public protocol LinearEnum: RawRepresentable<UInt8>, LinearEncoding {}

extension LinearEnum {
    static func parse(
        _ input: Data
    ) throws(LinearEncodingError) -> (Self, Int) {
        guard let prefix = input.first, let value = Self(rawValue: prefix) else {
            throw .unexpectedEOF
        }
        return (value, 1)
    }
    
    public var wireFormat: Data {
        get { Data([rawValue]) }
    }
}
