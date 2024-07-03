//
//  SignedAddresses.swift
//  
//
//  Created by Mark @ Germ on 6/27/24.
//

import Foundation

extension [ProtocolAddress]: SignableObject {
    public static let type: SignableObjectTypes = .addresses
    public var type: SignableObjectTypes { .addresses }
}
