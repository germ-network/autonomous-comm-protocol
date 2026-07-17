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
///
///The commitment is pinned to `.sha256` in both inits: the session layer
///accepts exactly SHA-256/32, so any other digest type is a wire-contract
///violation HERE — an immediate, local decode error — not a deep opaque
///failure at the A.4 side-band after establishment already succeeded.
public struct PQEstablishmentKeyMaterial: Equatable, Sendable {
	public let keyPackageData: Data
	public let bootstrapKpCommitment: TypedDigest

	///`bootstrapKpCommitment` takes the raw 32 digest bytes the session layer
	///hands out (and expects back); the `.sha256` wrapper — the only
	///commitment the A.4 verifier accepts — is applied here, so an illegal
	///create is unrepresentable rather than guarded downstream.
	public init(
		keyPackageData: Data,
		bootstrapKpCommitment: Data
	) throws {
		//an empty key package would encode as the OptionalData none-marker and
		//fail the RECIPIENT's parse — reject it locally, before the welcome is
		//signed and sent
		guard !keyPackageData.isEmpty else {
			throw LinearEncodingError.requiredValueMissing
		}
		self.keyPackageData = keyPackageData
		self.bootstrapKpCommitment = try TypedDigest(
			prefix: .sha256,
			checkedData: bootstrapKpCommitment
		)
	}

	init(keyPackageData: Data, bootstrapKpCommitment: TypedDigest) {
		self.keyPackageData = keyPackageData
		self.bootstrapKpCommitment = bootstrapKpCommitment
	}
}

extension PQEstablishmentKeyMaterial: LinearEncodedPair {
	public var first: Data { keyPackageData }
	public var second: TypedDigest { bootstrapKpCommitment }

	public init(first: Data, second: TypedDigest) throws {
		//pin the commitment's digest type on the wire: today .sha256 is the
		//only DigestTypes case, so this cannot fire — it exists for the day
		//the enum grows for some unrelated feature, keeping a non-SHA-256
		//commitment a decode error here rather than a signed, established
		//welcome that strands at A.4
		guard second.type == .sha256 else {
			throw LinearEncodingError.invalidPrefix
		}
		self.init(
			keyPackageData: first,
			bootstrapKpCommitment: second
		)
	}
}
