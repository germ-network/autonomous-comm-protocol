//
//  IdentityKeys+Migrate.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 9/14/24.
//

import CryptoKit
import Foundation

extension IdentityPrivateKey {
	//from an existing Identity so we don't invalidate existing agent delegations
	//and can upgrade to an MLS session
	//have to regenerate the new Core Identity format

	public static func migrate(
		existingKey: Curve25519.Signing.PrivateKey,
		name: String,
		jpegXLData: Data,
		imageAltText: String?
	) throws -> (IdentityPrivateKey, SignedObject<CoreIdentity>) {
		let identityPrivateKey = IdentityPrivateKey(concrete: existingKey)
		let coreIdentity = try CoreIdentity(
			id: identityPrivateKey.publicKey,
			name: name,
			describedImage: .init(imageData: jpegXLData, altText: imageAltText),
			version: CoreIdentity.Constants.currentVersion,
			nonce: .init(width: .bits128)
		)

		let coreIdentityData = try coreIdentity.wireFormat
		let signature = try identityPrivateKey.sign(input: coreIdentityData)

		return (
			identityPrivateKey,
			.init(
				content: coreIdentity,
				signature: signature
			)
		)
	}
}
