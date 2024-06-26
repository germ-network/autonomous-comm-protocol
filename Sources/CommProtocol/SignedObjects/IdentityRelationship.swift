//
//  IdentityRelationship.swift
//
//  Generalized framework for private keys A and B to attest to a relationship between them
//
//  Created by Mark Xue on 6/25/24.
//

import Foundation

public enum IdentityRelationshipTypes: UInt8, Codable {
    case delegateAgent
    case successorIdentity
    case successorAgent
}

public struct IdentityRelationshipAssertion {
    let relationship: IdentityRelationshipTypes
    let subject: TypedKeyMaterial
    let object: TypedKeyMaterial
    
    var wireFormat: Data {
        [relationship.rawValue] + subject.wireFormat + object.wireFormat
    }
    
    init(relationship: IdentityRelationshipTypes, subject: TypedKeyMaterial, object: TypedKeyMaterial) {
        self.relationship = relationship
        self.subject = subject
        self.object = object
    }
    
    init(wireformat: Data) throws(TypedKeyError) {
        guard let first = wireformat.first,
              let relationshipType = IdentityRelationshipTypes(rawValue: first) else {
            throw .invalidTypedKey
        }
        self.relationship = relationshipType
        let (firstKey, remainder) = try TypedKeyMaterial
            .readPrefix(data: Data(wireformat[1...]) )
        self.subject = firstKey
        guard let remainder else { throw .invalidTypedKey }
        self.object = try .init(wireformat: remainder)
    }
}

public struct SignedIdentityRelationship {
    
}
