//
//  CommProposalTests.swift
//  CommProtocol
//
//  Created by Mark Xue on 7/29/24.
//

import CryptoKit
import Testing

@testable import CommProtocol

struct CommProposalTests {
    let knownIdentity: IdentityPrivateKey
    let knownAgent: AgentPrivateKey

    init() {
        knownIdentity = .init(algorithm: .curve25519)
        knownAgent = .init(algorithm: .curve25519)
    }

    @Test func testSameAgent() throws {
        let mockMessage = Mocks.mockMessage()
        let mockContext = try TypedDigest.mock()
        let proposal = try knownAgent.proposeLeafNode(update: mockMessage)
        let wireProposal = try proposal.wireFormat

        let validated = try CommProposal.parseAndValidate(
            wireProposal,
            knownIdentity: knownIdentity.publicKey,
            knownAgent: knownAgent.publicKey,
            context: mockContext,
            updateMessage: mockMessage
        )

        print("Same Agent proposal size: \(wireProposal.count)")

        guard case .sameAgent = validated else {
            #expect(Bool(false))
            return
        }

    }

    @Test func testSameIdentity() async throws {
        let mockContext = try TypedDigest.mock()

        let (newAgent, identityDelegate) =
            try knownIdentity
            .createAgentDelegate(context: mockContext)

        let newAgentData = AgentUpdate.mock()
        let mockMessage = Mocks.mockMessage()

        let proposal = try newAgent.proposeAgentHandoff(
            existingIdentity: knownIdentity.publicKey,
            identityDelegate: identityDelegate,
            establishedAgent: knownAgent,
            context: mockContext,
            agentData: newAgentData,
            updateMessage: mockMessage
        )
        let wireProposal = try proposal.wireFormat

        let validated = try CommProposal.parseAndValidate(
            try proposal.wireFormat,
            knownIdentity: knownIdentity.publicKey,
            knownAgent: knownAgent.publicKey,
            context: mockContext,
            updateMessage: mockMessage
        )

        print("Same Agent proposal size: \(wireProposal.count)")

    }

}
