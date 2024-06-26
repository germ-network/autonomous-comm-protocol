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
    
    init(wireformat: Data) throws {
        guard let first = wireformat.first,
              let relationshipType = IdentityRelationshipTypes(rawValue: first) else {
            throw DefinedWidthError.invalidTypedKey
        }
        self.relationship = relationshipType
        let (subject, remainder) = try TypedKeyMaterial
            .parse(wireFormat: Data(wireformat[1...]) )
        self.subject = subject
        guard let remainder else { throw DefinedWidthError.invalidTypedKey }
        (object, objectData) = try TypedKeyMaterial.parse(wireFormat: remainder)
    }
}

//like TypedKeyMaterial, prepend a byte that indicates length of the body
public struct TypedSignature: DefinedWidthBinary, Sendable {
    public typealias Prefix = SigningKeyAlgorithm
    let signingAlgorithm: SigningKeyAlgorithm
    let signature: Data
    
    public var wireFormat: Data {
        [signingAlgorithm.rawValue] + signature
    }
    
    public init(prefix: SigningKeyAlgorithm, checkedData: Data) throws {
        guard prefix.contentByteSize == checkedData.count else {
            throw DefinedWidthError.incorrectDataLength
        }
        self.init(signingAlgorithm: prefix, signature: checkedData)
    }
    
    init(signingAlgorithm: SigningKeyAlgorithm, signature: Data) {
        self.signingAlgorithm = signingAlgorithm
        self.signature = signature
    }
}


public struct SignedIdentityRelationship {
    let subjectSignature: TypedSignature
    let objectSignature: TypedSignature
    let assertion: IdentityRelationshipAssertion
    
    public var wireFormat: Data {
        subjectSignature.wireFormat
        + objectSignature.wireFormat
        + assertion.wireFormat
    }
    
    public init(wireFormat: Data) throws {
        let (subjectSignature, remainder) = try TypedSignature
            .parse(wireFormat: wireFormat)
        self.subjectSignature = subjectSignature
        
        guard let remainder else { throw DefinedWidthError.invalidTypedSignature }
        let (objectSignature, assertionData) = try TypedSignature
            .parse(wireFormat: remainder)
        
        guard let assertionData else { throw DefinedWidthError.invalidTypedSignature }
        self.objectSignature = objectSignature
        
        self.assertion = try .init(wireformat: assertionData)
    }
    
    public init(
        subjectSignature: TypedSignature,
        objectSignature: TypedSignature,
        assertion: IdentityRelationshipAssertion
    ) {
        self.subjectSignature = subjectSignature
        self.objectSignature = objectSignature
        self.assertion = assertion
    }
}

public struct AgentData: Codable {
    let version: SemanticVersion
    let isAppClip: Bool? //omitted if false
}
