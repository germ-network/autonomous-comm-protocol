//
//  Convenience.swift
//
//
//  Created by Mark Xue on 6/23/24.
//

import CryptoKit
import Foundation

extension Digest {
	var data: Data { Data(bytes) }
	private var bytes: [UInt8] { Array(makeIterator()) }
}

// Ensure that SymmetricKey is generic password convertible.
extension SymmetricKey: RawRepresentableKey {
	public init<D>(rawRepresentation data: D) throws where D: ContiguousBytes {
		self.init(data: data)
	}

	public var rawRepresentation: Data {
		return dataRepresentation  // Contiguous bytes repackaged as a Data instance.
	}
}

extension ContiguousBytes {
	public var dataRepresentation: Data {
		withUnsafeBytes {
			Data(Array($0))
		}
	}
}
