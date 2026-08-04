//
//  AgentUpdateV2.swift
//  CommProtocol
//
//  The gated successor to `AgentUpdate` — grants only, no legacy `addresses`
//  field (docs/attachment-mailbox-delivery.md, "Wire types"). Carried by
//  `CommProposal.agentUpdateV2`, emitted only to a peer observed at or above
//  `AgentUpdate.mailboxGrantVersion`; a pre-gate peer keeps receiving the
//  classic triple (`.sameAgent`) byte-for-byte, unchanged.
//
//  BACKWARD COMPATIBILITY: this is a NEW `ProposalType` tag, same rule as
//  `PQCardUpgrade` (see its header comment). A peer that doesn't recognize the
//  tag drops the whole message on `LinearEnum` parse, so this case must ONLY
//  ever be emitted to a peer already confirmed at `mailboxGrantVersion`. The
//  capability gate lives in the app; this type is the wire carrier.
//

import Foundation

public struct AgentUpdateV2: Sendable, Equatable {
    public let version: SemanticVersion
    public let isAppClip: Bool
    public let grants: [MailboxGrant]

    public init(version: SemanticVersion, isAppClip: Bool, grants: [MailboxGrant]) {
        self.version = version
        self.isAppClip = isAppClip
        self.grants = grants
    }

    ///Mirrors `AgentUpdate.formatForSigning(updateMessage:context:)` — the
    ///signature binds the update to the MLS proposal (`updateMessage`) and
    ///the session `context`.
    func formatForSigning(
        updateMessage: Data,
        context: TypedDigest
    ) throws -> Data {
        try wireFormat + updateMessage + context.wireFormat
    }
}

// MARK: - Wire format

extension AgentUpdateV2 {
    private struct VersionArchive: Codable {
        let major: UInt32
        let minor: UInt32
        let patch: UInt32
        let preReleaseSuffix: String?

        //WIRE-FROZEN: never change a raw value once shipped.
        enum CodingKeys: String, CodingKey {
            case major = "j"
            case minor = "n"
            case patch = "p"
            case preReleaseSuffix = "r"
        }
    }

    private struct Archive: Codable {
        let version: VersionArchive
        let isAppClip: Bool
        let grants: [Data]  // each entry a MailboxGrant.wireFormat

        //WIRE-FROZEN: never change a raw value once shipped.
        enum CodingKeys: String, CodingKey {
            case version = "v"
            case isAppClip = "c"
            case grants = "g"
        }
    }

    private var cborEncoded: Data {
        get throws {
            try DeterministicCbor.encode(
                Archive(
                    version: VersionArchive(
                        major: version.major,
                        minor: version.minor,
                        patch: version.patch,
                        preReleaseSuffix: version.preReleaseSuffix
                    ),
                    isAppClip: isAppClip,
                    grants: try grants.map { try $0.wireFormat }
                )
            )
        }
    }

    private init(cborEncoded: Data) throws {
        let archive = try DeterministicCbor.decode(Archive.self, from: cborEncoded)
        self.init(
            version: SemanticVersion(
                major: archive.version.major,
                minor: archive.version.minor,
                patch: archive.version.patch,
                preReleaseSuffix: archive.version.preReleaseSuffix
            ),
            isAppClip: archive.isAppClip,
            grants: try archive.grants.map { try MailboxGrant(wireFormat: $0) }
        )
    }
}

// A CBOR value is self-delimiting to its own decoder, but `swift-cbor`'s
// public API doesn't report how many bytes a decode consumed out of a larger
// buffer — so, per the framing rule in `DeterministicCbor`, this rides as an
// opaque `Data` field: `Data: LinearEncodable` supplies the length prefix and
// the consumed-byte accounting that `SignedObject`/`CommProposal` need.
extension AgentUpdateV2: LinearEncodable {
    public static func parse(_ input: Data) throws -> (AgentUpdateV2, Int) {
        let (cbor, consumed) = try Data.parse(input)
        return (try AgentUpdateV2(cborEncoded: cbor), consumed)
    }

    public var wireFormat: Data {
        get throws { try cborEncoded.wireFormat }
    }
}
