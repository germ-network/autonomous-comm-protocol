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
    let objectData: Data? //additional data about the object
    //we can use this to assert the object version and if it is an app clip
    
    var wireFormat: Data {
        [relationship.rawValue] + subject.wireFormat + object.wireFormat + (objectData ?? Data())
    }
    
    init(
        relationship: IdentityRelationshipTypes,
        subject: TypedKeyMaterial,
        object: TypedKeyMaterial,
        objectData: Data?
    ) {
        self.relationship = relationship
        self.subject = subject
        self.object = object
        self.objectData = objectData
    }
    
    init(wireformat: Data) throws(TypedKeyError) {
        guard let first = wireformat.first,
              let relationshipType = IdentityRelationshipTypes(rawValue: first) else {
            throw .invalidTypedKey
        }
        self.relationship = relationshipType
        let (subject, remainder) = try TypedKeyMaterial
            .readPrefix(data: Data(wireformat[1...]) )
        self.subject = subject
        guard let remainder else { throw .invalidTypedKey }
        (object, objectData) = try TypedKeyMaterial.readPrefix(data: remainder)
    }
}

public struct SignedIdentityRelationship {
    
}
