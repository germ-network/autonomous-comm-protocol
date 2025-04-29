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
		.init(method: .plc, identifier: "example")
	}
}
