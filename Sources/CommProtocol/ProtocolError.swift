//
//  ProtocolError.swift
//
//
//  Created by Mark Xue on 6/12/24.
//

import Foundation

public enum ProtocolError: Error {
    case mismatchedSignedObjectType

    case typedKeyArchiveMismatch
    case typedKeyArchiveWireFormat
    case authenticationError
    case mismatchedDigest
    case signatureDisallowed
    case incorrectAssertionType
    case incorrectSigner
    case archiveIncorrect
    //    case missingData
    //    case incorrectKeyPackage
    //    case incorrectSignedBodyType
    //    case notImplemented
}

extension ProtocolError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .mismatchedSignedObjectType: "Mismatched signed object type"
        case .typedKeyArchiveMismatch: "Mismatched values for typed key archive"
        case .typedKeyArchiveWireFormat: "Couldn't create a typed key archive from wire format"
        case .authenticationError: "Signature validation failed"
        case .mismatchedDigest: "mismatched digest"
        case .signatureDisallowed: "Tried to use a signing key to sign an incorrect payload"
        case .incorrectAssertionType: "Incorrect identity relationship type"
        case .incorrectSigner: "Incorrect signing key type"
        case .archiveIncorrect: "unexpected archive"
        //        case .missingData:
        //            "ProtocolError: Missing data"
        //        case .incorrectKeyPackage:
        //            "ProtocolError: Incorrect key package"
        //        case .incorrectSignedBodyType:
        //            "ProtocolError: Incorrect signed body type"
        //        case .signatureCheckFailed:
        //            "ProtocolError: Signature check failed"
        //        case .digestNotEqual:
        //            "ProtocolError: Digest not equal"
        //        case .notImplemented:
        //            "ProtocolError: Not implemented"
        }
    }
}
