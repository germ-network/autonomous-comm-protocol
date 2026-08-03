//
//  DeterministicCbor.swift
//  CommProtocol
//

import Foundation
import SwiftCbor

/// The one seam through which any new CBOR wire type in this package encodes
/// or decodes. Not a general-purpose CBOR wrapper — a place to pin the
/// options and gotchas every such type must share, so no call site can drift
/// from them by picking its own defaults.
///
/// **New wire types are deterministic-CBOR maps with short string keys, not
/// integers.** `swift-cbor`'s Codable surface only ever produces or accepts
/// text-string map keys — its `KeyedEncodingContainer` keys off
/// `CodingKey.stringValue` exclusively, and its decoder silently *drops* any
/// map key that isn't a CBOR text string rather than erroring on one. An
/// integer-keyed map is wire-incompatible with this library by construction.
/// Keys are 1-2 lowercase letters, matching CoreAppLogic's existing CBOR
/// types (`AudioEnvelope`, `AudioMessage`) — e.g. `case authKey = "k"`. Once a
/// key has shipped, mark it `//WIRE-FROZEN` and never change the raw value.
///
/// **Archive-companion pattern.** A public wire type should not itself
/// conform to `Codable` — that lets any call site hand it to `JSONEncoder`,
/// or to `CborEncoder` without `.deterministicCbor`, and mint bytes nothing
/// here produced. Instead, keep a `private struct Archive: Codable` mirror
/// inside the same file as the only thing this seam ever sees, so there is
/// exactly one way to encode the type. See CoreAppLogic's `AudioEnvelope` for
/// the shape:
///
/// ```swift
/// public struct Example: Sendable, Equatable {
///     public let value: Data
///
///     private struct Archive: Codable {
///         let value: Data
///         enum CodingKeys: String, CodingKey {
///             case value = "v"  //WIRE-FROZEN
///         }
///     }
///
///     public var wireFormat: Data {
///         get throws { try DeterministicCbor.encode(Archive(value: value)) }
///     }
///
///     public init(wireFormat: Data) throws {
///         let archive = try DeterministicCbor.decode(Archive.self, from: wireFormat)
///         self.init(value: archive.value)
///     }
/// }
/// ```
///
/// **Framing a CBOR blob inside a positional (`LinearEncodable`) container.**
/// No new framing type is needed: wrap the encoded bytes as a plain `Data`
/// field. `Data: LinearEncodable`
/// (`MessageFraming/LinearEncodedData.swift`) already length-prefixes
/// arbitrary bytes — a 1-byte prefix, falling back internally to
/// `DeclaredWidthData` past 254 bytes — and reports consumed bytes correctly,
/// which is everything `LinearEncodable.parse` needs from a nested value. A
/// type whose wire form is entirely CBOR can conform to `LinearEncodable`
/// itself by riding this: `parse`/`wireFormat` simply delegate to `Data`'s.
public enum DeterministicCbor {
	/// Encodes under RFC 8949 §4.2.1 (`CborEncoder.Options.deterministicCbor`)
	/// — the only encode path any type using this seam may use.
	public static func encode<T: Encodable>(_ value: T) throws -> Data {
		try CborEncoder(options: .deterministicCbor).encode(value)
	}

	/// Decodes `type` from `data`.
	///
	/// Re-copies into a fresh, zero-based `Data` before handing it to
	/// `CborDecoder` — its scanner indexes zero-based and crashes on a
	/// non-zero-based slice (the same gotcha CoreAppLogic's
	/// `AudioEnvelope.init(sealedPlaintext:)` works around), which a caller
	/// handing this a subrange of a larger buffer would otherwise hit.
	public static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
		try CborDecoder().decode(type, from: Data(data))
	}
}
