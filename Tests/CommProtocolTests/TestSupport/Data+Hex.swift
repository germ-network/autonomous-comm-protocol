//
//  Data+Hex.swift
//  CommProtocol
//

import Foundation

/// Shared hex-fixture decoding for wire-pinning tests: hardcode the exact
/// encoded bytes of a wire type and assert equality, so a renamed
/// `CodingKeys` raw value or a reordered field fails HERE, in CI, rather than
/// silently drifting an already-shipped wire format. Hoisted out of
/// `AgentHelloDualOfferTests` — the first place this pattern appeared — so
/// new CBOR wire-pinning tests (`MailboxGrant`, `AgentUpdateV2`, ...) reuse it
/// instead of redefining it per file.
extension Data {
	init?(hexString: String) {
		guard hexString.count.isMultiple(of: 2) else { return nil }
		var bytes = [UInt8]()
		bytes.reserveCapacity(hexString.count / 2)
		var index = hexString.startIndex
		while index < hexString.endIndex {
			let next = hexString.index(index, offsetBy: 2)
			guard let byte = UInt8(hexString[index..<next], radix: 16) else {
				return nil
			}
			bytes.append(byte)
			index = next
		}
		self.init(bytes)
	}
}
