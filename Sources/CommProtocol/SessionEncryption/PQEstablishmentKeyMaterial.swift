//
//  PQEstablishmentKeyMaterial.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 7/17/26.
//

import Foundation

///The establishment key material a PQ (TwoMLSPQ v20) welcome carries, kept
///atomic so the commitment can never be separated from the key package it
///travels with:
/// - `keyPackageData`: the replier's CLASSICAL return key package (a bare MLS
///   KeyPackage message — the PQ half no longer rides the establishment reply)
/// - `bootstrapKpCommitment`: SHA-256 over the replier's pre-committed A.4
///   bootstrap PQ key package. The PQ key package itself follows in the A.4
///   side-band; the session layer rejects one that does not hash to this value.
///
///Both fields ride INSIDE the signed welcome body, binding the deferred PQ key
///material to the sender's identity root: a post-establishment channel
///compromise cannot substitute the PQ key package at A.4.
public struct PQEstablishmentKeyMaterial: Equatable, Sendable {
	public let keyPackageData: Data
	public let bootstrapKpCommitment: TypedDigest

	public init(
		keyPackageData: Data,
		bootstrapKpCommitment: TypedDigest
	) {
		self.keyPackageData = keyPackageData
		self.bootstrapKpCommitment = bootstrapKpCommitment
	}
}

extension PQEstablishmentKeyMaterial: LinearEncodedPair {
	public var first: Data { keyPackageData }
	public var second: TypedDigest { bootstrapKpCommitment }

	public init(first: Data, second: TypedDigest) throws {
		self.init(
			keyPackageData: first,
			bootstrapKpCommitment: second
		)
	}
}
