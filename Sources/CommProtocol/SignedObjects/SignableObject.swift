//
//  SignableObject.swift
//
//
//  Created by Mark @ Germ on 6/16/24.
//

import CryptoKit
import Foundation

public struct SignedObject<Content: LinearEncodable>: Sendable {
    let content: Content
    let signature: TypedSignature
}

extension SignedObject: LinearEncodable {
    public static func parse(_ input: Data) throws -> (
        SignedObject<Content>,
        Int
    ) {
        let (content, signature, consumed) = try LinearEncoder.decode(
            Content.self,
            TypedSignature.self,
            input: input
        )
        return (
            .init(content: content, signature: signature),
            consumed
        )
    }
    
    public var wireFormat: Data {
        get throws {
            try content.wireFormat + signature.wireFormat
        }
    }
}



//Deprecate from here down
public enum Signers {
    case identity
    case agent
}

public enum SignableObjectTypes: UInt8, Codable, Sendable {
    case identityRepresentation
    case identityDelegate
    case identityMutableData
    case identityPropose  //designate a successor
    case identitySuccessor  //designate

    case agentHello
    case agentPropose
    case agentSuccession
    case agentAttached  //new addresses, etc

    var signer: Signers {
        switch self {
        case .identityRepresentation, .identityDelegate, .identityMutableData, .identityPropose,
            .identitySuccessor:
            .identity
        case .agentHello, .agentPropose, .agentSuccession, .agentAttached: .agent
        }
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

    public init(prefix: SigningKeyAlgorithm, checkedData: Data) throws(LinearEncodingError) {
        guard prefix.contentByteSize == checkedData.count else {
            throw .incorrectDataLength
        }
        self.init(signingAlgorithm: prefix, signature: checkedData)
    }

    init(signingAlgorithm: SigningKeyAlgorithm, signature: Data) {
        self.signingAlgorithm = signingAlgorithm
        self.signature = signature
    }
}

//ensure signed objects state their type
public protocol DeprecateSignableObject {
    static var type: SignableObjectTypes { get }
}

///Encodes a wireformat of:
///[Byte indicating body type]
///[Byte indicating signature width][Signature bytes]
///[Body data]
public struct DeprecateSignedObject<S: DeprecateSignableObject>: Sendable {
    public let signature: TypedSignature
    public let body: Data  //signature is over this particular encoding of SignableObject

    init(signature: TypedSignature, body: Data) {
        self.signature = signature
        self.body = body
    }

    public var wireFormat: Data {
        [S.type.rawValue] + signature.wireFormat + body
    }

    init(wireFormat: Data) throws {
        guard let first = wireFormat.first,
            let readBodyType = SignableObjectTypes(rawValue: first),
            wireFormat.count > 1
        else {
            throw LinearEncodingError.invalidTypedSignature
        }
        guard readBodyType == S.type else {
            throw LinearEncodingError.invalidTypedKey
        }
        let (signature, body) =
            try TypedSignature
            .continuingParse(Data(wireFormat[1...]))
        self.signature = signature
        self.body = body
    }

    func validate(
        for signer: any PublicSigningKey
    ) throws -> Data {
        guard signature.signingAlgorithm == type(of: signer).signingAlgorithm else {
            throw LinearEncodingError.invalidTypedKey
        }
        guard signer.isValidSignature(signature.signature, for: body) else {
            throw ProtocolError.authenticationError
        }
        return body
    }
}

extension DeprecateSignedObject where S: Decodable {
    public func validate(
        for signer: any PublicSigningKey
    ) throws -> S {
        try validate(for: signer).decoded()
    }
}

extension DeprecateSignedObject where S: WireFormat {
    public func validate(
        for signer: any PublicSigningKey
    ) throws -> S {
        let value: Data = try validate(for: signer)
        return try .init(wireFormat: value)
    }
}
