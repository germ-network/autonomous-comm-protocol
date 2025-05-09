//
//  AnchorPolicy.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 5/7/25.
//

import Foundation

public enum AnchorPolicy: UInt8, LinearEnum {
	case closed = 0
	case follows
	case open
}

extension AnchorPolicy: Codable, Sendable {}
