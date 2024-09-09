//
//  CommProposalTests.swift
//  CommProtocol
//
//  Created by Mark Xue on 7/29/24.
//

import CryptoKit
import Foundation
import Testing

@testable import CommProtocol

struct CommProposalTests {
    let knownIdentityKey: IdentityPrivateKey
    let knownSignedIdentity: SignedObject<CoreIdentity>
    let knownAgent: AgentPrivateKey

    init() throws {
        (knownIdentityKey, knownSignedIdentity) =
            try Mocks
            .mockIdentity()

        knownAgent = .init(algorithm: .curve25519)
    }

    @Test func testSameAgent() throws {
        let mockMessage = Mocks.mockMessage()
        let mockContext = try TypedDigest.mock()

        let signedIdentityMutable = try knownIdentityKey.sign(mutableData: .mock())

        let proposal = try knownAgent.proposeLeafNode(
            leafNodeUpdate: mockMessage,
            agentUpdate: .mock(),
            signedIdentityMutable: signedIdentityMutable,
            context: mockContext
        )
        let wireProposal = try proposal.wireFormat

        let validated = try CommProposal.finalParse(wireProposal)
            .validate(
                knownIdentity: knownSignedIdentity.content.id,
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

    @Test func testSameAgentErrors() throws {
        let mockMessage = Mocks.mockMessage()
        let mockContext = try TypedDigest.mock()
        let proposal = try knownAgent.proposeLeafNode(
            leafNodeUpdate: mockMessage,
            agentUpdate: .mock(),
            signedIdentityMutable: try knownIdentityKey.sign(mutableData: .mock()),
            context: mockContext
        )
        let wireProposal = try proposal.wireFormat

        let wrongKey = AgentPrivateKey(algorithm: .curve25519)

        #expect(throws: ProtocolError.authenticationError) {
            let _ = try CommProposal.finalParse(wireProposal)
                .validate(
                    knownIdentity: knownSignedIdentity.content.id,
                    knownAgent: wrongKey.publicKey,
                    context: mockContext,
                    updateMessage: mockMessage
                )
        }

        #expect(throws: ProtocolError.authenticationError) {
            let _ = try CommProposal.finalParse(wireProposal)
                .validate(
                    knownIdentity: knownSignedIdentity.content.id,
                    knownAgent: knownAgent.publicKey,
                    context: .mock(),
                    updateMessage: mockMessage
                )
        }
    }

    @Test func testSameIdentity() async throws {
        let mockContext = try TypedDigest.mock()

        let (newAgent, identityDelegate) =
            try knownIdentityKey
            .createAgentDelegate(context: mockContext)

        let newAgentData = AgentUpdate.mock()
        let mockMessage = Mocks.mockMessage()

        let proposal = try newAgent.completeAgentHandoff(
            input: .init(
                existingIdentity: knownSignedIdentity.content.id,
                identityDelegate: identityDelegate,
                signedIdentityMutable: try knownIdentityKey.sign(mutableData: .mock()),
                establishedAgent: knownAgent.publicKey
            ),
            context: mockContext,
            agentData: newAgentData,
            updateMessage: mockMessage
        )
        let wireProposal = try proposal.wireFormat
        print("Same Identity proposal size: \(wireProposal.count)")

        let outcome = try CommProposal.finalParse(wireProposal)
            .validate(
                knownIdentity: knownSignedIdentity.content.id,
                knownAgent: knownAgent.publicKey,
                context: mockContext,
                updateMessage: mockMessage
            )
        guard
            case .sameIdentity(
                let validatedAgent,
                let validatedMutable
            ) = outcome
        else {
            #expect(Bool(false))
            return
        }
        #expect(validatedAgent.newAgent == newAgent.publicKey)
        #expect(validatedAgent.agentData == newAgentData)
    }

    @Test func testSameIdentityErrors() async throws {
        let mockContext = try TypedDigest.mock()

        let (newAgent, identityDelegate) =
            try knownIdentityKey
            .createAgentDelegate(
                context: mockContext
            )

        let newAgentData = AgentUpdate.mock()
        let mockMessage = Mocks.mockMessage()

        let proposal = try newAgent.completeAgentHandoff(
            input: .init(
                existingIdentity: knownSignedIdentity.content.id,
                identityDelegate: identityDelegate,
                signedIdentityMutable: try knownIdentityKey.sign(mutableData: .mock()),
                establishedAgent: knownAgent.publicKey
            ),
            context: mockContext,
            agentData: newAgentData,
            updateMessage: mockMessage
        )

        #expect(throws: ProtocolError.authenticationError) {
            let _ = try proposal.validate(
                knownIdentity: knownSignedIdentity.content.id,
                knownAgent: knownAgent.publicKey,
                context: .mock(),
                updateMessage: mockMessage
            )
        }
    }

    @Test func testNewIdentity() async throws {
        let (nextIdentityKey, signedNextIdentity) = try Mocks.mockIdentity()

        let mockContext = try TypedDigest.mock()

        let knownIdentitySignature = try knownIdentityKey.startHandoff(
            to: nextIdentityKey.publicKey,
            context: mockContext
        )

        let newAgent = AgentPrivateKey(algorithm: .curve25519)

        let identityHandoff = try nextIdentityKey.createHandoff(
            existingIdentity: knownIdentityKey.publicKey,
            newAgent: newAgent.publicKey,
            startSignature: knownIdentitySignature,
            signedIdentity: signedNextIdentity,
            identityMutable: .mock(),
            context: mockContext
        )

        let mockMessage = Mocks.mockMessage()

        let proposal = try newAgent.completeIdentityHandoff(
            identityHandoff: identityHandoff,
            establishedAgent: knownAgent.publicKey,
            context: mockContext,
            agentData: .mock(),
            updateMessage: mockMessage
        )
        let wireProposal = try proposal.wireFormat

        print("New Identity proposal size: \(wireProposal.count)")

        let outcome = try CommProposal.finalParse(wireProposal)
            .validate(
                knownIdentity: knownSignedIdentity.content.id,
                knownAgent: knownAgent.publicKey,
                context: mockContext,
                updateMessage: mockMessage
            )

        guard
            case .newIdentity(
                let identity,
                let signedIdentity,
                let validatedAgentHandoff
            ) = outcome
        else {
            #expect(Bool(false))
            return
        }
    }
}
