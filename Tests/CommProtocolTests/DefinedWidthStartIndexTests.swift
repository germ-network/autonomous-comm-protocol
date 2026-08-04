//
//  DefinedWidthStartIndexTests.swift
//  CommProtocol
//
//  Created by Mark Xue on 8/4/26.
//

import CryptoKit
import Foundation
import Testing

@testable import CommProtocol

///`Data` is its own SubSequence, so a value carved out of a larger buffer keeps
///that buffer's indices. A conforming type that stored such a view would hand
///every consumer a `checkedData` whose valid range starts past zero — safe for
///`.first`/`.count`/`for`-in, a trap for `[0]` or `[0..<n]`. Both construction
///paths must therefore re-base, and they must agree with each other.
struct DefinedWidthStartIndexTests {
	@Test func bothConstructionPathsAreZeroBased() throws {
		let original = DataIdentifier(width: .bits256)

		let viaInit = try DataIdentifier(wireFormat: original.wireFormat)
		let (viaParse, _) = try DataIdentifier.parse(wireFormat: original.wireFormat)

		#expect(viaInit.identifier.startIndex == 0)
		#expect(viaParse.identifier.startIndex == 0)
		#expect(viaInit.identifier == original.identifier)
		#expect(viaParse.identifier == original.identifier)
	}

	///The regression proper: decoding out of the middle of a larger buffer is
	///what makes a non-zero startIndex reachable in the first place.
	@Test func aWireFormatCarvedFromABufferStillDecodesZeroBased() throws {
		let original = DataIdentifier(width: .bits256)
		let padded = Data(repeating: 0xAA, count: 7) + original.wireFormat
		let embedded = padded.suffix(from: 7)

		#expect(embedded.startIndex == 7)

		let decoded = try DataIdentifier(wireFormat: embedded)
		#expect(decoded.identifier.startIndex == 0)
		#expect(decoded.identifier == original.identifier)
		//the operation that traps on a view
		#expect(decoded.identifier[0] == original.identifier[0])
	}

	///Same guarantee for the other widely-used conformer, whose payload feeds
	///key material rather than an identifier.
	@Test func typedKeyMaterialIsZeroBasedFromASlice() throws {
		let key = SymmetricKey(size: .bits256)
		let original = try TypedKeyMaterial(algorithm: .chaCha20Poly1305, symmetricKey: key)
		let padded = Data(repeating: 0x55, count: 3) + original.wireFormat

		let decoded = try TypedKeyMaterial(wireFormat: padded.suffix(from: 3))
		#expect(decoded.keyData.startIndex == 0)
		#expect(decoded.keyData == original.keyData)
	}
}
