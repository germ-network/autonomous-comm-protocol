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

//like TypedKeyMaterial, prepend a byte that indicates length of the body
public struct TypedSignature: Sendable {
    let signingAlgorithm: SigningKeyAlgorithm
    let signature: Data
    
    var wireFormat: Data {
        [signingAlgorithm.rawValue] + signature
    }
    
    init(signingAlgorithm: SigningKeyAlgorithm, signature: Data) {
        self.signingAlgorithm = signingAlgorithm
        self.signature = signature
    }
    
    init(wireFormat: Data) throws(TypedKeyError) {
        guard let first = wireFormat.first,
              let signingAlgorithm = SigningKeyAlgorithm(rawValue: first),
              wireFormat.count == signingAlgorithm.signatureLength + 1 else {
            throw .invalidTypedSignature
        }
        self.signingAlgorithm = signingAlgorithm
        self.signature = Data( wireFormat[1...] )
    }
    
    static func readPrefix(
        data: Data
    ) throws(TypedKeyError) -> (TypedSignature, Data?) {
        guard let first = data.first,
              let prefixAlgo = SigningKeyAlgorithm(rawValue: first) else {
            throw .invalidTypedSignature
        }
        let prefixLength = prefixAlgo.signatureLength + 1
        switch data.count {
        case (..<prefixLength):
            throw TypedKeyError.invalidTypedKey
        case prefixLength:
            return (try .init(wireFormat: data), nil)
        case ((prefixLength + 1)...):
            return (
                try .init(wireFormat: Data(data.prefix(prefixLength)) ) ,
                Data(data[prefixLength...])
            )
        default: throw TypedKeyError.invalidTypedKey
        }
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
    
    public init(wireFormat: Data) throws(TypedKeyError) {
        let (subjectSignature, remainder) = try TypedSignature
            .readPrefix(data: wireFormat)
        self.subjectSignature = subjectSignature
        
        guard let remainder else { throw .invalidTypedSignature }
        let (objectSignature, assertionData) = try TypedSignature
            .readPrefix(data: remainder)
        
        guard let assertionData else { throw .invalidTypedSignature }
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
