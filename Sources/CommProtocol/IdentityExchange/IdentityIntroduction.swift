//
//  IdentityIntroduction.swift
//  CommProtocol
//
//  Created by Mark Xue on 8/3/24.
//

import CryptoKit
import Foundation

//Shared across AgentHello, AgentHelloReply,
//and IdentityUpdate when transmitting a new identity
///Encapsulate the data needed to process a new identity
public struct IdentityIntroduction: Equatable {
    //Standalone object
    public let signedIdentity: SignedObject<CoreIdentity>
    public let signedContents: SignedObject<Contents>

    //remainder of data the new Identity signs over
    public struct Contents: Equatable {
        //for type simplicity, this allows an optional image resource,
        //but it is required here and will fail validation if it doesn't exist
        public let mutableData: IdentityMutableData
        public let agentKey: AgentPublicKey

        func formatForSigning(context: TypedDigest?) throws -> Data {
            try wireFormat + (context?.wireFormat ?? .init())
        }
    }

    public func validated(context: TypedDigest?) throws -> (
        CoreIdentity,
        Contents,
        Resource
    ) {
        let verifiedIdentity = try signedIdentity.verifiedIdentity()
        let contents = try verifiedIdentity.id.validate(
            signedIntroduction: signedContents,
            context: context
        )
        
        guard let imageResource = contents.mutableData.imageResource else {
            throw ProtocolError.missingImageResource
        }

        return (verifiedIdentity, contents, imageResource)
    }
}

extension IdentityIntroduction: LinearEncodedPair {
    public var first: SignedObject<CoreIdentity> { signedIdentity }
    public var second: SignedObject<Contents> { signedContents }

    public init(
        first: SignedObject<CoreIdentity>,
        second: SignedObject<Contents>
    ) throws {
        self.init(
            signedIdentity: first,
            signedContents: second
        )
    }
}

extension IdentityIntroduction.Contents: LinearEncodedPair {
    public var first: IdentityMutableData { mutableData }
    public var second: TypedKeyMaterial { agentKey.id }

    public init(
        first: IdentityMutableData,
        second: TypedKeyMaterial
    ) throws {
        try self.init(
            mutableData: first,
            agentKey: .init(archive: second)
        )
    }
}
