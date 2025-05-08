//
//  AnchorPolicy.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 5/7/25.
//

import Foundation

public enum AnchorPolicy: UInt8, LinearEnum, Sendable {
	case closed = 0
	case follows = 1
}
