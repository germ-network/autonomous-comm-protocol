//
//  ProtocolError.swift
//
//
//  Created by Mark Xue on 6/12/24.
//

import Foundation

public enum ProtocolError: Error {
	case mismatchedSignedObjectType
	case missingImageResource
	case typedKeyArchiveMismatch
	case typedKeyArchiveWireFormat
	case authenticationError
	case mismatchedDigest
	case signatureDisallowed
	case incorrectAssertionType
	case incorrectSigner
	case archiveIncorrect
	case incorrectAnchorType
	case incorrectAnchorState
	case missingOptional(String)
	case unexpected(String)
}

extension ProtocolError: Equatable {}

extension ProtocolError: LocalizedError {
	public var errorDescription: String? {
		switch self {
		case .mismatchedSignedObjectType: "Mismatched signed object type"
		case .missingImageResource: "Missing Image Resource"
		case .typedKeyArchiveMismatch: "Mismatched values for typed key archive"
		case .typedKeyArchiveWireFormat:
			"Couldn't create a typed key archive from wire format"
		case .authenticationError: "Signature validation failed"
		case .mismatchedDigest: "mismatched digest"
		case .signatureDisallowed: "Tried to use a signing key to sign an incorrect payload"
		case .incorrectAssertionType: "Incorrect identity relationship type"
		case .incorrectSigner: "Incorrect signing key type"
		case .archiveIncorrect: "unexpected archive"
		case .incorrectAnchorType: "Incorrect anchor type"
		case .incorrectAnchorState: "Incorrect anchor state"
		case .missingOptional(let string): "Missing optional \(string)"
		case .unexpected(let string): "Unexpected \(string)"
		}
	}
}
