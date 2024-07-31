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
    let knownIdentityKey: IdentityPrivateKey
    let knownIdentity: CoreIdentity
    let knownSignedIdentity: SignedIdentity
    let knownAgent: AgentPrivateKey

    init() throws {
        (knownIdentityKey, knownIdentity, knownSignedIdentity) =
            try Mocks
            .mockIdentity()

        knownAgent = .init(algorithm: .curve25519)
    }

    @Test func testSameAgent() throws {
        let mockMessage = Mocks.mockMessage()
        let mockContext = try TypedDigest.mock()
        let proposal = try knownAgent.proposeLeafNode(update: mockMessage)
        let wireProposal = try proposal.wireFormat

        let validated = try CommProposal.parseAndValidate(
            wireProposal,
            knownIdentity: knownIdentity.id,
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
            try knownIdentityKey
            .createAgentDelegate(context: mockContext)

        let newAgentData = AgentUpdate.mock()
        let mockMessage = Mocks.mockMessage()

        let existingSignature = try knownAgent.startAgentHandoff(
            newAgent: newAgent.publicKey,
            context: mockContext
        )

        let proposal = try newAgent.completeAgentHandoff(
            existingIdentity: knownIdentity.id,
            identityDelegate: identityDelegate,
            establishedAgent: knownAgent.publicKey,
            establishedSignature: existingSignature,
            context: mockContext,
            agentData: newAgentData,
            updateMessage: mockMessage
        )
        let wireProposal = try proposal.wireFormat
        print("Same Identity proposal size: \(wireProposal.count)")

        let outcome = try CommProposal.parseAndValidate(
            try proposal.wireFormat,
            knownIdentity: knownIdentity.id,
            knownAgent: knownAgent.publicKey,
            context: mockContext,
            updateMessage: mockMessage
        )
        guard case .sameIdentity(let validated) = outcome else {
            #expect(Bool(false))
            return
        }
        #expect(validated.newAgent == newAgent.publicKey)
        #expect(validated.agentData == newAgentData)
    }

    @Test func testNewIdentity() async throws {
        let (nextIdentityKey, nextIdentity, signedNextIdentity) = try Mocks.mockIdentity()

        let mockContext = try TypedDigest.mock()

        let knownIdentitySignature = try knownIdentityKey.startHandoff(
            to: nextIdentityKey.publicKey,
            context: mockContext
        )

        let (newAgent, identityHandoff) = try nextIdentityKey.createHandoff(
            existingIdentity: knownIdentityKey.publicKey,
            startSignature: knownIdentitySignature,
            signedIdentity: signedNextIdentity,
            context: mockContext
        )

        let mockMessage = Mocks.mockMessage()
        let existingAgentSignature = try knownAgent.startAgentHandoff(
            newAgent: newAgent.publicKey,
            context: mockContext
        )

        let proposal = try newAgent.completeIdentityHandoff(
            newIdentity: nextIdentity.id,
            identityHandoff: identityHandoff,
            establishedAgent: knownAgent.publicKey,
            establishedAgentSignature: existingAgentSignature,
            context: mockContext,
            agentData: .mock(),
            updateMessage: mockMessage
        )
        let wireProposal = try proposal.wireFormat

        print("New Identity proposal size: \(wireProposal.count)")

        let outcome = try CommProposal.parseAndValidate(
            wireProposal,
            knownIdentity: knownIdentity.id,
            knownAgent: knownAgent.publicKey,
            context: mockContext,
            updateMessage: mockMessage
        )
    }
}
