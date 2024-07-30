//
//  CommProposalTests.swift
//  CommProtocol
//
//  Created by Mark Xue on 7/29/24.
//

import Testing
import CryptoKit
@testable import CommProtocol

struct CommProposalTests {
    let knownIdentity: IdentityPrivateKey
    let knownAgent: AgentPrivateKey
    
    init() {
        knownIdentity = .init(algorithm: .curve25519)
        knownAgent = .init(algorithm: .curve25519)
    }

    @Test func testSameAgent() async throws {
        let mockMessage = SymmetricKey(size: .bits256).rawRepresentation
        let proposal = try knownAgent.proposeLeafNode(update: mockMessage)
        
        let validated = try CommProposal.parseAndValidate(
            proposal.wireFormat,
            knownIdentity: knownIdentity.publicKey,
            knownAgent: knownAgent.publicKey,
            updateMessage: mockMessage
        )
        guard case .sameAgent = validated else {
            #expect(Bool(false))
            return
        }
        
    }

}