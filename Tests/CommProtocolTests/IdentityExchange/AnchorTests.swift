//
//  AnchorTests.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 3/7/25.
//

import CommProtocol
import Testing

struct AnchorTests {

    @Test func testAnchorVerification() throws {
        let (privateKey, signedAnchor) = try ATProtoAnchor.signedMock()
        let verified = try privateKey.publicKey.verify(signedAnchor: signedAnchor)
        #expect(verified == signedAnchor.content)
    }

}
