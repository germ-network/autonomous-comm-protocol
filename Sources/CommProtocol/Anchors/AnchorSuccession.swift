//
//  AnchorSuccession.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 5/7/25.
//

import Foundation

//We start with a signature by the previous over the next, covering the context
//This has several presentations
// - with the next key for a handoff
// - with the previous key, recursive, for a continuity proof
public enum AnchorSuccession {  //enum for namespace
	static let discriminator = "AnchorSuccession"

	private struct SignatureBody: LinearEncodedQuad {
		let first: String  //Self.discriminator
		let second: AnchorAttestation.Archive
		let third: TypedKeyMaterial  //predecessor
		let fourth: TypedKeyMaterial  //successor
	}

	static func signatureBody(
		attestation: AnchorAttestation,
		predecessor: AnchorPublicKey,
		successor: AnchorPublicKey,
	) throws -> Data {
		try SignatureBody(
			first: Self.discriminator,
			second: attestation.archive,
			third: predecessor.archive,
			fourth: successor.archive
		).wireFormat
	}

	//instead of a recursive structure, we store an array of them
	public struct Proof: Sendable {
		let predecessor: TypedKeyMaterial
		let signature: TypedSignature  //signed proof
	}
}

extension AnchorSuccession.Proof: LinearEncodedPair {
	public var first: TypedKeyMaterial { predecessor }
	public var second: TypedSignature { signature }

	public init(first: TypedKeyMaterial, second: TypedSignature) throws {
		self.init(predecessor: first, signature: second)
	}
}

//save the date alongside the Proof so we can apply policy to prune
public struct DatedProof: LinearEncodedPair, Sendable {
	public var first: AnchorSuccession.Proof
	public var second: Date

	public init(first: AnchorSuccession.Proof, second: Date) {
		self.first = first
		self.second = second
	}

	public typealias Filter = (Date) -> Bool
}
