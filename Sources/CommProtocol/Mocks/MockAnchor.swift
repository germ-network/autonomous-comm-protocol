//
//  MockAnchor.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 3/6/25.
//

import CryptoKit
import Foundation

extension ATProtoDID {
	public static func mock() -> ATProtoDID {
		.init(
			method: .plc,
			identifier: .init(
				(0..<24).compactMap{ _ in base32Set.randomElement()}
			)
		)
	}
	
	//generate test did per the spec https://github.com/did-method-plc/did-method-plc
	static let lowercaseAlpha = (UInt8(ascii: "a")...UInt8(ascii: "z"))
		.map{Character(UnicodeScalar($0))}
	static let base32Set: [Character] = lowercaseAlpha + ["2", "3", "4", "5", "6", "7"]
}
