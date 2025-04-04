//
//  IdentityKey.swift
//
//
//  Created by Mark Xue on 6/12/24.
//

import CryptoKit
import Foundation

///# Key Abstractions
///We introduce type abstractions atop the basic CryptoKit primitive so we have type-enforced domain separation
///and introduce cryptographic agility by abstracting the typed object into a protocol
///- Bare CryptoKit Key
/// - Can be archived in string format (typically rawRepresentable -> Base64 encoded
/// - pseudo-stable (modulo padding)
///- RoledSigningKey
/// - Type contains data about key role, public/private, and algorithm
/// - archives to a string (also pseudo-stable, modulo raw key padding in Base64)

//TODO: type constrain the keys to have the same algorithm.
protocol PrivateSigningKey: TypedKeyMaterialInput, Sendable {
	associatedtype PublicKey where PublicKey: PublicSigningKey
	static var signingAlgorithm: SigningKeyAlgorithm { get }

	init()
	var rawRepresentation: Data { get }
	var publicKey: PublicKey { get }

	func signature<D>(for data: D) throws -> Data where D: DataProtocol
}

public protocol PublicSigningKey: TypedKeyMaterialInput, Hashable, Sendable {
	static var signingAlgorithm: SigningKeyAlgorithm { get }

	init<D>(rawRepresentation data: D) throws where D: ContiguousBytes
	var rawRepresentation: Data { get }

	func isValidSignature<S, D>(
		_ signature: S,
		for data: D
	) -> Bool where S: DataProtocol, D: DataProtocol
}

//use enum to pick keys, but rely on TypedKeyMaterial enum to encode
//Do use this to encode prefix when
public enum SigningKeyAlgorithm: UInt8, DefinedWidthPrefix, Sendable {
	case curve25519  //RFC 8410

	public var contentByteSize: Int { signatureLength }

	private var signatureLength: Int {
		switch self {
		case .curve25519: 64
		}
	}
}

//used the typed key material format for storing private keys in KeyChain / secrets stores
//rely on object types when constructing wire formats to prevent accidental use of
//private keys when public keys are expected,
//instead of encoding in the wire format and make sure we then check the generated wire format
extension Curve25519.KeyAgreement.PrivateKey: TypedKeyMaterialInput {
	public static let encodeAlgorithm: TypedKeyMaterial.Algorithms = .chaCha20Poly1305
}
