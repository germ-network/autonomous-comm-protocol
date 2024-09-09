//
//  AgentPropose.swift
//  CommProtocol
//
//  Created by Mark Xue on 7/27/24.
//

import Foundation

///Order of operations:
///Start with a validated ID<>Agent<>LN having signed each other, for a given MLS groupID
///
///Order the data as follows

/// 1. Branch point new or same identity. convey this in enum
///     1 c. same Agent: existing agent over MLS update message
///     1 b. same identity: existing identity signature over the
///     1 a. new identity
///         1a.i: Old Identity Key over new Identity Key + context
///         1aii: New Identity key over old identity key + context + agent key

/// 2. Known Agent Key signs new Agent Key + context
/// 3. New Agent key signs a bundle, covering:
///     * known agent key
///     * context
///     * new agent's identity key
///     * new agent's associated data
///     * new agent's update message (enclosing the leafNode + MLS signing identity)
///
///
///Output:
///\[CommProposal.ProposalType.rawValue\]
/// * branch point
///     * \[TypedSignature.wireFormat\] \(sameAgent\)
///     * \[Identity
///[knownAgentSignature.wireFormat]
///

public enum CommProposal: LinearEncodable, Equatable {
    //we don't, strictly speaking, need the type enum on the typed signature,
    //but this lets us parse the data structure without injecting the expected
    //types into our parse methods
    //SignedObject includes signature over the new update message
    case sameAgent(SignedObject<AgentUpdate>, SignedObject<IdentityMutableData>?)
    //used with multi-agents
    case sameIdentity(IdentityDelegate, AgentHandoff, SignedObject<IdentityMutableData>?)
    //Identity Handoff includes an IdentityMutable data
    case newIdentity(IdentityHandoff, AgentHandoff)

    enum ProposalType: UInt8, LinearEnum {
        case sameAgent = 1
        case sameIdentity
        case newIdentity
    }

    public enum Validated: Sendable {
        case sameAgent(AgentUpdate, IdentityMutableData?)
        case sameIdentity(AgentHandoff.Validated, IdentityMutableData?)
        case newIdentity(SignedObject<CoreIdentity>, AgentHandoff.Validated)
    }

    public func validate(
        knownIdentity: IdentityPublicKey,
        knownAgent: AgentPublicKey,
        context: TypedDigest,
        updateMessage: Data
    ) throws -> Validated {
        switch self {
        case .sameAgent(let signedAgentUpdate, let signedIdentityMutable):
            .sameAgent(
                try knownAgent.validate(
                    signedAgentUpdate: signedAgentUpdate,
                    for: updateMessage,
                    context: context
                ),
                try knownIdentity.validate(maybeSignedObject: signedIdentityMutable)

            )
        case .sameIdentity(let identityDelegate, let agentHandoff, let identityMutable):
            try Self.validateSameIdentity(
                knownIdentity: knownIdentity,
                knownAgent: knownAgent,
                context: context,
                updateMessage: updateMessage,
                identityDelegate: identityDelegate,
                agentHandoff: agentHandoff,
                signedIdentityMutable: identityMutable
            )
        case .newIdentity(let identityHandoff, let agentHandoff):
            try Self.validateNewIdentity(
                knownIdentity: knownIdentity,
                knownAgent: knownAgent,
                context: context,
                updateMessage: updateMessage,
                identityHandoff: identityHandoff,
                agentHandoff: agentHandoff
            )

        }
    }

    public static func parse(_ input: Data) throws -> (CommProposal, Int) {
        let (type, remainder) = try ProposalType.continuingParse(input)
        switch type {
        case .sameAgent:
            let (signedAgentUpdate, signedIdentityMutable, consumed) =
                try LinearEncoder
                .decode(
                    SignedObject<AgentUpdate>.self,
                    (SignedObject<IdentityMutableData>?).self,
                    input: remainder
                )
            return (.sameAgent(signedAgentUpdate, signedIdentityMutable), consumed + 1)
        case .sameIdentity:
            return try parseSameIdentity(remainder)
        case .newIdentity:
            return try parseNewIdentity(remainder)
        }

    }

    public var wireFormat: Data {
        get throws {
            switch self {
            case .sameAgent(let signedAgentData, let signedIdentityMutable):
                try [ProposalType.sameAgent.rawValue]
                    + signedAgentData.wireFormat + signedIdentityMutable.wireFormat
            case .sameIdentity(let identityDelegate, let agentHandoff, let signedIdentityMutable):
                try [ProposalType.sameIdentity.rawValue]
                    + identityDelegate.wireFormat
                    + agentHandoff.wireFormat
                    + signedIdentityMutable.wireFormat
            case .newIdentity(let identityHandoff, let agentHandoff):
                try [ProposalType.newIdentity.rawValue]
                    + identityHandoff.wireFormat
                    + agentHandoff.wireFormat
            }
        }
    }

    //MARK: Parse Implementation
    //increment the return value to include the enum so we can directly pass it back
    private static func parseSameIdentity(_ input: Data) throws -> (
        CommProposal,
        Int
    ) {
        let (identityDelegate, agentHandoff, identityMutable, consumed) =
            try LinearEncoder
            .decode(
                IdentityDelegate.self,
                AgentHandoff.self,
                (SignedObject<IdentityMutableData>?).self,
                input: input
            )
        return (
            .sameIdentity(
                identityDelegate,
                agentHandoff,
                identityMutable
            ),
            consumed + 1
        )
    }

    private static func parseNewIdentity(_ input: Data)
        throws -> (CommProposal, Int)
    {
        let (newIdentity, agentHandoff, consumed) =
            try LinearEncoder
            .decode(
                IdentityHandoff.self,
                AgentHandoff.self,
                input: input
            )
        return (.newIdentity(newIdentity, agentHandoff), consumed + 1)
    }

    //MARK: Validate Implementation
    private static func validateSameIdentity(
        knownIdentity: IdentityPublicKey,
        knownAgent: AgentPublicKey,
        context: TypedDigest,
        updateMessage: Data,
        identityDelegate: IdentityDelegate,
        agentHandoff: AgentHandoff,
        signedIdentityMutable: SignedObject<IdentityMutableData>?
    ) throws -> Validated {
        let newAgent = try identityDelegate.validate(
            knownIdentity: knownIdentity,
            context: context
        )

        let agentUpdate = try agentHandoff.validate(
            knownAgent: knownAgent,
            newAgent: newAgent,
            newAgentIdentity: knownIdentity,
            context: context,
            updateMessage: updateMessage
        )

        let validatedAgent = AgentHandoff.Validated(
            newAgent: newAgent,
            agentData: agentUpdate
        )

        return .sameIdentity(
            validatedAgent,
            try knownIdentity.validate(maybeSignedObject: signedIdentityMutable)
        )
    }

    private static func validateNewIdentity(
        knownIdentity: IdentityPublicKey,
        knownAgent: AgentPublicKey,
        context: TypedDigest,
        updateMessage: Data,
        identityHandoff: IdentityHandoff,
        agentHandoff: AgentHandoff
    ) throws -> Validated {
        let validatedIdentity = try identityHandoff.validate(
            knownIdentity: knownIdentity,
            context: context
        )

        let agentUpdate = try agentHandoff.validate(
            knownAgent: knownAgent,
            newAgent: validatedIdentity.newAgentKey,
            newAgentIdentity: validatedIdentity.signedNewIdentity.content.id,
            context: context,
            updateMessage: updateMessage
        )

        return .newIdentity(
            validatedIdentity.signedNewIdentity,
            .init(
                newAgent: validatedIdentity.newAgentKey,
                agentData: agentUpdate
            )
        )
    }
}
