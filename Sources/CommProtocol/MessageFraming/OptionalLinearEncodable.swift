//
//  OptionalLinearEncodable.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 7/31/24.
//

import Foundation

/// The generic version of this prepends a byte to indicate missing or not
extension Optional: LinearEncodable where Wrapped: LinearEncodable {
	public static func parse(_ input: Data) throws -> (Wrapped?, Int) {
		guard let prefix = input.first else {
			throw LinearEncodingError.unexpectedEOF
		}
		switch prefix {
		case 0:
			return (nil, 1)
		case 1:
			let (result, consumed) =
				try Wrapped
				.parse(input.suffix(from: input.startIndex + 1))
			return (result, consumed + 1)
		default: throw LinearEncodingError.unexpectedData
		}
	}

	public var wireFormat: Data {
		get throws {
			switch self {
			case .none: Data([UInt8(0)])
			case .some(let wrapped):
				try Data([UInt8(1)]) + wrapped.wireFormat
			}
		}
	}

}
