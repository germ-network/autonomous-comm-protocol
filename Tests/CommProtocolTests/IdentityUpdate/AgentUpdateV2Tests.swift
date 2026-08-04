//
//  AgentUpdateV2Tests.swift
//  CommProtocol
//

import CommProtocolMocks
import CryptoKit
import Foundation
import Testing

@testable import CommProtocol

struct AgentUpdateV2Tests {
    let knownIdentityKey: IdentityPrivateKey
    let knownSignedIdentity: SignedObject<CoreIdentity>
    let knownAgent: AgentPrivateKey

    init() throws {
        (knownIdentityKey, knownSignedIdentity) = try Mocks.mockIdentity()
        knownAgent = .init()
    }

    // MARK: - CBOR round-trip

    @Test func testCborRoundTrip() throws {
        let original = AgentUpdateV2.mock()
        let encoded = try original.wireFormat
        let (decoded, consumed) = try AgentUpdateV2.parse(encoded)
        #expect(consumed == encoded.count)
        #expect(decoded == original)
    }

    /// `SemanticVersion.mock()` includes a pre-release suffix only at random,
    /// so the mock round-trip above exercises the version archive's "r" key
    /// probabilistically — this pins both branches deterministically.
    @Test func testCborRoundTripVersionSuffixBothWays() throws {
        for suffix in [String?.none, "-beta.1"] {
            let original = AgentUpdateV2(
                version: SemanticVersion(
                    major: 2, minor: 4, patch: 0, preReleaseSuffix: suffix
                ),
                isAppClip: false,
                grants: [.mock()]
            )
            let (decoded, _) = try AgentUpdateV2.parse(try original.wireFormat)
            #expect(decoded == original)
            #expect(decoded.version.string == original.version.string)
        }
    }

    @Test func testGrantsOnlyNoLegacyAddressesField() {
        // Structural check that the type itself has no way to carry a legacy
        // address list — the whole point of the gated cutover
        // (docs/attachment-mailbox-delivery.md, "Wire types"). If this ever
        // fails to compile, `AgentUpdateV2` grew an `addresses` field.
        let update = AgentUpdateV2.mock()
        let mirror = Mirror(reflecting: update)
        #expect(mirror.children.map { $0.label } == ["version", "isAppClip", "grants"])
    }

    // MARK: - Wire-pinning

    @Test func testCborWireFormatGolden() throws {
        let key = try TypedKeyMaterial(
            algorithm: .hmacSha256,
            symmetricKey: SymmetricKey(data: Data(count: 32))
        )
        let grant = try MailboxGrant(
            authKey: key,
            serviceHost: "ger.mx",
            expiration: RoundedDate(hoursSinceEpoch: 471442)
        )
        let update = AgentUpdateV2(
            version: SemanticVersion(major: 2, minor: 4, patch: 0),
            isAppClip: false,
            grants: [grant]
        )
        let encoded = try update.wireFormat
        // Locks the encoding against drift, same discipline as
        // MailboxGrantTests.testCborWireFormatGolden. Byte-verified at
        // introduction with an independent CBOR parse: a length-prefixed
        // `Data` (0x4b = 75 bytes) wrapping a 3-key canonical map ("c" <
        // "g" < "v" bytewise) — isAppClip=false, a one-element grants array
        // whose entry is exactly the golden `MailboxGrant` bytes, and the
        // version {major:2, minor:4, patch:0}.
        #expect(
            encoded
                == Data(
                    hexString:
                        "4ba36163f46167815836a361651a000731926168666765722e6d78616b58210500000000000000000000000000000000000000000000000000000000000000006176a3616a02616e04617000"
                )
        )
    }

    /// The `ProposalType` tags of every case that predates this one must not
    /// move — that's what "legacy peers keep receiving the classic triple
    /// byte-identically" actually depends on, since `.agentUpdateV2` is
    /// appended, not inserted.
    @Test func testExistingProposalTagsUnchanged() {
        #expect(CommProposal.ProposalType.sameAgent.rawValue == 1)
        #expect(CommProposal.ProposalType.sameIdentity.rawValue == 2)
        #expect(CommProposal.ProposalType.newIdentity.rawValue == 3)
        #expect(CommProposal.ProposalType.anchorHandOff.rawValue == 4)
        #expect(CommProposal.ProposalType.pqCardUpgrade.rawValue == 5)
        #expect(CommProposal.ProposalType.agentUpdateV2.rawValue == 6)
    }

    /// A hex pin of `.sameAgent`'s deterministic portion (the `ProposalType`
    /// tag byte + `AgentUpdate`'s own encoding) under fixed inputs — proving
    /// the pre-existing case's bytes are unaffected by this file's changes.
    /// Extends the golden-hex pattern in `AgentHelloDualOfferTests`.
    ///
    /// Stops short of pinning the trailing `TypedSignature`: CryptoKit's
    /// Ed25519 does not reproduce identical signature bytes for the same key
    /// and message across runs (verified empirically — two runs against this
    /// exact fixture diverged only in that trailing region), unlike RFC
    /// 8032's nominally-deterministic algorithm. The `validate` call below
    /// is the correctness check for that region instead: it can only succeed
    /// if the signature, whatever its bytes, verifies against exactly this
    /// `AgentUpdate` and signing key.
    @Test func testSameAgentProposalGoldenHexUnaffected() throws {
        let fixedAgent = try AgentPrivateKey(
            archive: .init(prefix: .curve25519Signing, checkedData: Data(count: 32))
        )
        let fixedAddress = ProtocolAddress(
            identifier: "00000000-0000-0000-0000-000000000000",
            serviceHost: "ger.mx",
            expiration: RoundedDate(hoursSinceEpoch: 471442)
        )
        let fixedAgentUpdate = AgentUpdate(
            version: SemanticVersion(major: 1, minor: 0, patch: 0),
            isAppClip: false,
            addresses: [fixedAddress]
        )
        let fixedMessage = Data([0x01, 0x02, 0x03])
        let fixedContext = TypedDigest(prefix: .sha256, over: Data([0x00]))

        let proposal = try fixedAgent.proposeLeafNode(
            leafNodeUpdate: fixedMessage,
            agentUpdate: fixedAgentUpdate,
            signedIdentityMutable: nil,
            context: fixedContext
        )
        let encoded = try proposal.wireFormat
        #expect(encoded.count == 122)  // tag(1) + AgentUpdate(56) + TypedSignature(65)
        #expect(
            encoded.prefix(57)
                == Data(
                    hexString:
                        "010100000000012430303030303030302d303030302d303030302d303030302d303030303030303030303030066765722e6d78ff0007319200"
                )
        )

        // And it still validates — this proposal is unaffected end to end,
        // not merely byte-identical by coincidence.
        let (parsed, consumed) = try CommProposal.parse(encoded)
        #expect(consumed == encoded.count)
        guard case .sameAgent(let signedUpdate, nil) = parsed else {
            Issue.record("expected .sameAgent")
            return
        }
        let verified = try fixedAgent.publicKey.validate(
            signedAgentUpdate: signedUpdate,
            for: fixedMessage,
            context: fixedContext
        )
        #expect(verified == fixedAgentUpdate)
    }

    // MARK: - CommProposal.agentUpdateV2 round-trip

    @Test func testAgentUpdateV2Proposal() throws {
        let mockMessage = Mocks.mockMessage()
        let mockContext = try TypedDigest.mock()
        let signedIdentityMutable = try knownIdentityKey.sign(mutableData: .mock())

        let proposal = try knownAgent.proposeAgentUpdateV2(
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

        guard case .agentUpdateV2(let agentUpdate, let mutableData) = validated else {
            Issue.record("expected .agentUpdateV2")
            return
        }
        #expect(!agentUpdate.grants.isEmpty)
        #expect(mutableData != nil)
    }

    @Test func testAgentUpdateV2ProposalRejectsWrongKey() throws {
        let mockMessage = Mocks.mockMessage()
        let mockContext = try TypedDigest.mock()

        let proposal = try knownAgent.proposeAgentUpdateV2(
            leafNodeUpdate: mockMessage,
            agentUpdate: .mock(),
            signedIdentityMutable: nil,
            context: mockContext
        )
        let wireProposal = try proposal.wireFormat
        let wrongKey = AgentPrivateKey()

        #expect(throws: ProtocolError.authenticationError) {
            let _ = try CommProposal.finalParse(wireProposal)
                .validate(
                    knownIdentity: knownSignedIdentity.content.id,
                    knownAgent: wrongKey.publicKey,
                    context: mockContext,
                    updateMessage: mockMessage
                )
        }
    }

    // MARK: - mailboxGrantVersion gate

    @Test func testSupportsMailboxGrantsBoundary() {
        let below = AgentUpdate(
            version: SemanticVersion(major: 2, minor: 3, patch: 9999),
            isAppClip: false,
            addresses: []
        )
        let at = AgentUpdate(
            version: AgentUpdate.mailboxGrantVersion,
            isAppClip: false,
            addresses: []
        )
        let above = AgentUpdate(
            version: SemanticVersion(major: 2, minor: 4, patch: 1),
            isAppClip: false,
            addresses: []
        )
        #expect(!below.supportsMailboxGrants)
        #expect(at.supportsMailboxGrants)
        #expect(above.supportsMailboxGrants)
    }

    @Test func testMailboxGrantVersionOrdering() {
        // Sits between the two existing PQ thresholds, per the design doc.
        #expect(AgentUpdate.pqCapableVersion < AgentUpdate.mailboxGrantVersion)
        #expect(AgentUpdate.mailboxGrantVersion < AgentUpdate.pqDomainSeparationVersion)
    }
}
