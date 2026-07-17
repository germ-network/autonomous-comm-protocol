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
	///Reserved wire tag leading the encoding; the parse init rejects anything
	///else. This byte — not enum raw values — is what makes the classical and
	///PQ welcome layouts mutually unparseable at their divergence point, where
	///a classical welcome carries a bare key-package `Data`. It MUST be `0x00`,
	///the one byte a classical `Data` length prefix can never be: `OptionalData`
	///encodes a non-empty body with a length prefix of `0x01…0xFE` (or `0xFF`
	///wide-form), and an empty body is rejected upstream — so a leading `0x00`
	///can only mean PQ key material, never a classical key package. Both
	///cross-parse directions then reject deterministically, with no reliance on
	///the signature check:
	/// - classical bytes read as PQ: the leading byte is the classical length
	///   prefix (never `0x00`), so this guard fails with `invalidPrefix`;
	/// - PQ bytes read as classical: a classical `Data` parse reads this `0x00`
	///   as the `OptionalData` none-marker and throws `requiredValueMissing`.
	///
	///A nonzero value would collide: a key package of exactly that length has
	///that length prefix, so the element round-trips byte-identically through
	///the PQ parse and the classical agent signature validates as PQ — a
	///cross-route confusion the signature check does NOT catch. Frozen: changing
	///it breaks every signed PQ welcome.
	public static let discriminator: UInt8 = 0x00

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

extension PQEstablishmentKeyMaterial: LinearEncodedTriple {
	public var first: UInt8 { Self.discriminator }
	public var second: Data { keyPackageData }
	public var third: TypedDigest { bootstrapKpCommitment }

	public init(first: UInt8, second: Data, third: TypedDigest) throws {
		guard first == Self.discriminator else {
			throw LinearEncodingError.invalidPrefix
		}
		//pin the commitment's digest type on the wire: today .sha256 is the
		//only DigestTypes case, so this cannot fire — it exists for the day
		//the enum grows for some unrelated feature, keeping a non-SHA-256
		//commitment a decode error here rather than a signed, established
		//welcome that strands at A.4
		guard third.type == .sha256 else {
			throw LinearEncodingError.invalidPrefix
		}
		self.init(
			keyPackageData: second,
			bootstrapKpCommitment: third
		)
	}
}
