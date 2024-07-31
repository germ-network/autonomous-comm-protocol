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

public enum CommProposal: LinearEncodable {
    //we don't, strictly speaking, need the type enum on the typed signature,
    //but this lets us parse the data structure without injecting the expected
    //types into the
    case sameAgent(TypedSignature)  //over the new update message
    case sameIdentity(IdentityDelegate, AgentHandoff)  //used with multi-agents
    case newIdentity(IdentityHandoff, AgentHandoff)

    enum ProposalType: UInt8, LinearEnum {
        case sameAgent = 1
        case sameIdentity
        case newIdentity
    }

    public enum Validated {
        case sameAgent
        case sameIdentity(AgentHandoff.Validated)
        case newIdentity(CoreIdentity, SignedIdentity, AgentHandoff.Validated)
    }

    public static func parseAndValidate(
        _ input: Data,
        knownIdentity: IdentityPublicKey,
        knownAgent: AgentPublicKey,
        context: TypedDigest,
        updateMessage: Data
    ) throws -> Validated {
        let result = try finalParse(input)
        switch result {
        case .sameAgent(let signature):
            guard
                knownAgent.publicKey.isValidSignature(
                    signature.signature,
                    for: updateMessage + context.wireFormat),
                signature.signingAlgorithm == knownAgent.type
            else {
                throw ProtocolError.authenticationError
            }
            return .sameAgent
        case .sameIdentity(let identityDelegate, let agentHandoff):
            return try validateSameIdentity(
                knownIdentity: knownIdentity,
                knownAgent: knownAgent,
                context: context,
                updateMessage: updateMessage,
                identityDelegate: identityDelegate,
                agentHandoff: agentHandoff
            )
        case .newIdentity(let identityHandoff, let agentHandoff):
            return try validateNewIdentity(
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
            let (signature, width) = try TypedSignature.parse(remainder)
            return (.sameAgent(signature), width + 1)
        case .sameIdentity:
            return try parseSameIdentity(remainder)
        case .newIdentity:
            return try parseNewIdentity(remainder)
        }

    }

    public var wireFormat: Data {
        get throws {
            switch self {
            case .sameAgent(let typedSignature):
                [ProposalType.sameAgent.rawValue]
                    + typedSignature.wireFormat
            case .sameIdentity(let identityDelegate, let agentHandoff):
                [ProposalType.sameIdentity.rawValue]
                    + identityDelegate.wireFormat
                    + agentHandoff.wireFormat
            case .newIdentity(let identityHandoff, let agentHandoff):
                [ProposalType.newIdentity.rawValue]
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
        let (identityDelegate, agentHandoff, consumed) =
            try LinearEncoder
            .decode(
                IdentityDelegate.self,
                AgentHandoff.self,
                input: input
            )
        return (.sameIdentity(identityDelegate, agentHandoff), consumed + 1)
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
        agentHandoff: AgentHandoff
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

        let validated = AgentHandoff.Validated(
            newAgent: newAgent,
            agentData: agentUpdate
        )
        return .sameIdentity(validated)
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
            newAgentIdentity: validatedIdentity.newIdentity.id,
            context: context,
            updateMessage: updateMessage
        )

        return .newIdentity(
            validatedIdentity.newIdentity,
            validatedIdentity.signedNewIdentity,
            .init(
                newAgent: validatedIdentity.newAgentKey,
                agentData: agentUpdate
            )
        )
    }
}

