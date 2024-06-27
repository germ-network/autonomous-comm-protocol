//
//  File.swift
//  
//
//  Created by Mark @ Germ on 6/27/24.
//

import Foundation

public struct Addresses: SignableObject, Codable {
    public static let type: SignableObjectTypes = .addresses
    public var type: SignableObjectTypes = .addresses
    public let addresses: [ProtocolAddress]
}
