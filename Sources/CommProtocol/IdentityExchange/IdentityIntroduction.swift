//
//  IdentityIntroduction.swift
//  CommProtocol
//
//  Created by Mark Xue on 8/3/24.
//

import Foundation

//Shared across AgentHello, AgentHelloReply,
//and IdentityUpdate when transmitting a new identity
///Encapsulate the data needed to process a new identity
public struct IdentityIntroduction {
    //Standalone object
    let signedIdentity: SignedObject<CoreIdentity>
    let signedContents: SignedObject<Contents>

    //remainder of data the new Identity signs over
    public struct Contents {
        let mutableData: IdentityMutableData
        let agentKey: AgentPublicKey

        func formatForSigning(context: TypedDigest?) throws -> Data {
            try mutableData.wireFormat + agentKey.wireFormat
                + (context?.wireFormat ?? .init())
        }
    }

    func validated(context: TypedDigest?) throws -> (
        CoreIdentity,
        Contents
    ) {
        let verifiedIdentity = try signedIdentity.verifiedIdentity()
        let contents = try verifiedIdentity.id.validate(signedObject: signedContents)

        return (verifiedIdentity, contents)
    }
}

extension IdentityIntroduction: LinearEncodedPair {
    var first: SignedObject<CoreIdentity> { signedIdentity }
    var second: SignedObject<Contents> { signedContents }

    init(
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
    var first: IdentityMutableData { mutableData }
    var second: TypedKeyMaterial { agentKey.id }

    init(first: IdentityMutableData, second: TypedKeyMaterial) throws {
        try self.init(
            mutableData: first,
            agentKey: .init(archive: second)
        )
    }
}