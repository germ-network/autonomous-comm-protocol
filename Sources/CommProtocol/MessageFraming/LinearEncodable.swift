//
//  LinearEncoding.swift
//  CommProtocol
//
//  Created by Mark Xue on 7/28/24.
//

import Foundation

///A format for consuming a stream of binary data into a known structure, with some branch points

public protocol LinearEncodable {
	static func parse(_ input: Data) throws -> (Self, Int)
	var wireFormat: Data { get throws }
}

extension LinearEncodable {
	public static func continuingParse(_ input: Data) throws -> (Self, Data) {
		let (result, remainder) = try optionalParse(input)
		guard let remainder else {
			throw LinearEncodingError.unexpectedEOF
		}
		return (result, remainder)
	}

	public static func finalParse(_ input: Data) throws -> Self {
		let (result, remainder) = try optionalParse(input)
		guard remainder == nil else {
			throw LinearEncodingError.unexpectedData
		}
		return result
	}

	public static func finalParse(_ input: Data?) throws -> Self? {
		guard let input else { return nil }
		return try finalParse(input)
	}

	public static func optionalParse(_ input: Data) throws -> (Self, Data?) {
		let (result, consumed) = try parse(input)
		guard input.count > consumed else { return (result, nil) }
		return (result, input.suffix(from: input.startIndex + consumed))
	}
}

//allows us to parse LinearEncodable in a functional interface
extension Data {
	public func parseWireFormat<L: LinearEncodable>() throws -> L {
		try L.finalParse(self)
	}
}

//used in CommProtocol
public struct LinearEncoder {
	static func decode<T: LinearEncodable, U: LinearEncodable>(
		_ firstType: T.Type,
		_ secondType: U.Type,
		input: Data
	) throws -> (T, U, Int) {
		let (first, consumed) = try T.parse(input)
		guard consumed < input.count else {
			throw LinearEncodingError.unexpectedEOF
		}
		let slice = input.suffix(from: input.startIndex + consumed)
		let (second, secondConsumed) = try U.parse(slice)

		return (first, second, consumed + secondConsumed)
	}

	static func decode<T: LinearEncodable, U: LinearEncodable, V: LinearEncodable>(
		_ firstType: T.Type,
		_ secondType: U.Type,
		_ thirdType: V.Type,
		input: Data
	) throws -> (T, U, V, Int) {
		let (first, consumed) = try T.parse(input)
		guard consumed < input.count else {
			throw LinearEncodingError.unexpectedEOF
		}
		let slice = input.suffix(from: input.startIndex + consumed)

		let (second, secondConsumed) = try U.parse(slice)
		guard secondConsumed < slice.count else {
			throw LinearEncodingError.unexpectedEOF
		}
		let finalSlice = slice.suffix(from: slice.startIndex + secondConsumed)

		let (third, thirdConsumed) = try V.parse(finalSlice)

		return (first, second, third, consumed + secondConsumed + thirdConsumed)
	}
}

public enum LinearEncodingError: Error, Equatable {
	case mismatchedAlgorithms(
		expected: TypedKeyMaterial.Algorithms,
		found: TypedKeyMaterial.Algorithms)
	case unknownTypedKeyAlgorithm(UInt8)
	case invalidTypedKey
	case invalidTypedSignature
	case invalidPrefix
	case incorrectDataLength
	case bodyTooLarge
	case unexpectedData
	case unexpectedEOF
	case requiredValueMissing
	case notImplemented  //shim
}

extension LinearEncodingError: LocalizedError {
	public var errorDescription: String? {
		switch self {
		case .mismatchedAlgorithms(let expected, let found):
			"Mismatched key algorithm, expected \(expected), found \(found)"
		case .unknownTypedKeyAlgorithm(let index):
			"Unknown Typed Key Algorithm \(index)"
		case .invalidTypedKey: "Invalid typed key"
		case .invalidTypedSignature: "Invalid typed signature"
		case .invalidPrefix: "Invalid prefix"
		case .incorrectDataLength: "Incorrect Data Length"
		case .bodyTooLarge: "Data body too large"
		case .unexpectedData: "Additional data found at end of parse"
		case .unexpectedEOF: "Unexpected end of input"
		case .requiredValueMissing: "Required Value Missing"
		case .notImplemented: "Not Implemented"
		}
	}
}

public protocol LinearEnum: RawRepresentable<UInt8>, LinearEncodable {}

extension LinearEnum {
	public static func parse(
		_ input: Data
	) throws(LinearEncodingError) -> (Self, Int) {
		guard let prefix = input.first, let value = Self(rawValue: prefix) else {
			throw .unexpectedEOF
		}
		return (value, 1)
	}

	public var wireFormat: Data {
		Data([rawValue])
	}
}
