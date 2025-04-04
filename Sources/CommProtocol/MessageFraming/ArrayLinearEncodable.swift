//
//  ArrayLinearEncodable.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 7/31/24.
//

import Foundation

extension Array: LinearEncodable where Element: LinearEncodable {
	public static func parse(_ input: Data) throws -> ([Element], Int) {
		guard let prefix = input.first else {
			throw LinearEncodingError.unexpectedEOF
		}
		switch prefix {
		case 0: return ([], 1)
		case .max: throw LinearEncodingError.notImplemented
		default:
			var result = Self()
			var traverseIndex = 1
			for _ in 0..<prefix {
				let (value, consumed) = try Element.parse(
					input.suffix(from: input.startIndex + traverseIndex)
				)
				result.append(value)
				traverseIndex += consumed
			}
			return (result, traverseIndex)
		}
	}

	public var wireFormat: Data {
		get throws {
			//reserve UInt8.max as canary value
			guard count < UInt8.max else {
				throw LinearEncodingError.bodyTooLarge
			}
			guard !isEmpty else {
				return Data([UInt8(0)])
			}

			let prefix = Data([UInt8(count)])
			let encoded = try reduce(prefix) { partialResult, element in
				try partialResult + element.wireFormat
			}

			return encoded
		}
	}

}
