//
//  DefinedWidthBinary.swift
//
//
//  Created by Mark @ Germ on 6/26/24.
//

import Foundation

///Objects with a variable but but predictable data encoding width denoted by a byte enum
///that is prepended
///
///Allows us to keep binary data in binary format as an alternative to JSON encoding
public protocol DefinedWidthBinary: WireFormat, LinearEncodable {
	associatedtype Prefix: DefinedWidthPrefix
	var wireFormat: Data { get }
	//where checkedData has the exected width
	init(prefix: Prefix, checkedData: Data) throws(LinearEncodingError)
	static func parse(_ input: Data) throws -> (Self, Int)
}

public protocol DefinedWidthPrefix: RawRepresentable<UInt8> {
	var contentByteSize: Int { get }
}

///basically rawRepresentable<Data>, but with throwing init
///DefinedWidthBinary are all wireformat. We also have a set of objects that combine DefinedWidthBinary
///and concatenate them, optionally with a variable width suffix
///e.g. SignedIdentity, which has a suffix of the encoded Identity over which the signed digest is computed
public protocol WireFormat {
	var wireFormat: Data { get }
	init(wireFormat: Data) throws
}

extension DefinedWidthBinary {
	public init(wireFormat: Data) throws(LinearEncodingError) {
		guard let prefix = wireFormat.first,
			let prefixType = Prefix(rawValue: prefix)
		else {
			throw .invalidPrefix
		}
		guard wireFormat.count == prefixType.contentByteSize + 1 else {
			throw .incorrectDataLength
		}
		try self.init(
			prefix: prefixType,
			checkedData: wireFormat.suffix(from: wireFormat.startIndex + 1)
		)
	}

	//defaut implementation of LinearEncoding conformance
	public static func parse(_ input: Data) throws -> (Self, Int) {
		return try parse(wireFormat: input)
	}

	public static func parse(wireFormat: Data)
		throws(LinearEncodingError) -> (Self, Int)
	{
		guard let prefix = wireFormat.first,
			let prefixType = Prefix(rawValue: prefix)
		else {
			throw .invalidPrefix
		}
		let knownWidth = 1 + prefixType.contentByteSize
		switch wireFormat.count {
		case (..<knownWidth):
			throw .incorrectDataLength
		default:
			let start = wireFormat.startIndex + 1
			let end = wireFormat.startIndex + knownWidth
			return (
				try .init(
					prefix: prefixType,
					checkedData: Data(wireFormat[start..<end])
				),
				knownWidth
			)
		}
	}
}
