//
//  PQEstablishmentHandoff.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 7/20/26.
//

import Foundation

///The establishment binding for a born-dedicated PQ session's delegation
///(TwoMLSPQ contract 26). A born-dedicated acceptor's session runs under a
///freshly-minted dedicated agent from its very first frame, so — unlike every
///other credential the receive path admits — there is no proposal round to
///carry the identity-signed handoff. Instead the handoff artifact rides the
///establishment wire itself, stapled next to the (unmodified, spec-conformant)
///return welcome, and its signatures BIND THE WELCOME through ONE derivation:
///the `context` slot carries `sha256(welcome)`, so the delegation cannot be
///detached from the exact group being joined or replayed against another
///session.
///
///There is deliberately no `updateMessage` binding (ruling 2026-07-20): at
///establishment the welcome IS the credential-carrying MLS artifact — the role
///the Upd digest plays in a steady-state rotation — and it is already signed
///via `context`, so a second welcome-derived fill would bind nothing new. The
///card arm signs an EMPTY `updateMessage`, which is itself separating: every
///steady-state fill is a 33-byte digest, so the establishment TBS differs from
///any rotation TBS in length before collision resistance is even needed — and
///no other flow verifies an `AgentHandoff` with an empty slot, making the
///establishment verifier the only door such a signature can pass. The
///`IdentityDelegate` never had an `updateMessage` slot; its separation rests,
///as everywhere in this protocol, on the context VALUE (`sha256(welcome)` vs a
///group-id digest — disjoint preimage spaces under SHA-256).
public enum PQEstablishmentBinding {
	///The one establishment binding, filling BOTH arms' slots: the digest of
	///the exact welcome the initiator will join. Card: the
	///`IdentityDelegate`/`AgentHandoff` `context`. Anchor: `groupContext` AND
	///`mlsUpdateDigest` (the slot is a required `TypedDigest`, so the honest
	///fill is the same single binding value stated at both fixed TBS offsets —
	///cross-validating as a steady-state handoff would need the welcome digest
	///to equal a group-id digest and an Upd digest simultaneously). The
	///verifier recomputes it from the welcome section of the establishment
	///staple — the value is never transmitted separately, so there is nothing
	///to substitute.
	public static func context(welcome: Data) -> TypedDigest {
		.init(prefix: .sha256, over: welcome)
	}
}

///The CARD arm's born-dedicated establishment delegation: the same two
///artifacts a steady-state card rotation carries — the `IdentityDelegate`
///(the identity key signs the dedicated agent key + context) and the
///`AgentHandoff` (the dedicated agent's proof-of-possession signature over
///the known/invitation agent, the identity, the context, and an EMPTY
///update-message slot — see `PQEstablishmentBinding` for why empty is both
///honest and separating) — with the context filled from the welcome. The
///invitation agent does not sign (steady-state parity: a card predecessor
///never signs the successor's handoff), but it is NAMED in the signed body
///(`knownAgentKey`), so the artifact only validates against the invitation
///agent the initiator already holds.
///
///Transport: rides the establishment staple's opaque signed-blob section,
///next to (never inside) the spec-conformant return welcome. The leading
///reserved byte makes the two arms' blobs mutually unparseable at their first
///byte, before any signature check.
public struct PQCardEstablishmentHandoff: Equatable, Sendable {
	///Reserved leading wire byte; the parse init rejects anything else.
	///Distinct from `PQAnchorEstablishmentHandoff.discriminator`, so a blob
	///for one arm dies deterministically at the other's parse. Frozen.
	public static let discriminator: UInt8 = 0x01

	let identityDelegate: IdentityDelegate
	let agentHandoff: AgentHandoff

	public struct Validated: Sendable {
		///The dedicated agent the identity delegated to. The caller MUST
		///additionally require this key to equal the welcome's creator-leaf
		///credential (the session layer's `expectedCreator` re-feed check) —
		///the signatures prove the identity delegated this key for this
		///welcome, and only the leaf equality proves the session actually
		///runs under it.
		public let newAgent: AgentPublicKey
		public let agentData: AgentUpdate
	}

	///Validate against the peer state the initiator already holds: the
	///acceptor's identity (from the card introduction) and its invitation
	///agent (the key package's delegated agent), plus the welcome bytes from
	///the establishment staple's welcome section.
	public func validated(
		knownIdentity: IdentityPublicKey,
		knownAgent: AgentPublicKey,
		welcome: Data
	) throws -> Validated {
		let context = PQEstablishmentBinding.context(welcome: welcome)
		let newAgent = try identityDelegate.validate(
			knownIdentity: knownIdentity,
			context: context
		)
		let agentData = try agentHandoff.validate(
			knownAgent: knownAgent,
			newAgent: newAgent,
			newAgentIdentity: knownIdentity,
			context: context,
			updateMessage: Data()
		)
		return .init(newAgent: newAgent, agentData: agentData)
	}
}

extension PQCardEstablishmentHandoff: LinearEncodedTriple {
	public var first: UInt8 { Self.discriminator }
	public var second: IdentityDelegate { identityDelegate }
	public var third: AgentHandoff { agentHandoff }

	public init(first: UInt8, second: IdentityDelegate, third: AgentHandoff) throws {
		guard first == Self.discriminator else {
			throw LinearEncodingError.invalidPrefix
		}
		self.init(identityDelegate: second, agentHandoff: third)
	}
}

///The ANCHOR arm's born-dedicated establishment delegation: the full
///steady-state `AnchorHandoff` — the invitation (retired) agent, the active
///anchor, and the dedicated (new) agent all sign — with `groupContext` and
///`mlsUpdateDigest` both filled with the ONE establishment binding value
///(`PQEstablishmentBinding.context(welcome:)`; the digest slot is required, so
///the honest fill is the same value at both fixed TBS offsets).
public struct PQAnchorEstablishmentHandoff: Equatable, Sendable {
	///Reserved leading wire byte; see `PQCardEstablishmentHandoff`. Frozen.
	public static let discriminator: UInt8 = 0x02

	let anchorHandoff: AnchorHandoff

	///Validate against the peer state the initiator already holds: the
	///acceptor's anchor (from the hello) paired with its invitation agent,
	///plus the welcome bytes from the establishment staple. The returned
	///`Verified.agent.agentKey` is the dedicated agent; the caller MUST
	///additionally require it to equal the welcome's creator-leaf credential
	///(the session layer's `expectedCreator` re-feed check).
	public func validated(
		knownAnchor: PublicAnchorAgent,
		welcome: Data
	) throws -> AnchorHandoff.Verified {
		let context = PQEstablishmentBinding.context(welcome: welcome)
		return try knownAnchor.verify(
			anchorHandoff: anchorHandoff,
			context: context,
			mlsUpdateDigest: context
		)
	}
}

extension PQAnchorEstablishmentHandoff: LinearEncodedPair {
	public var first: UInt8 { Self.discriminator }
	public var second: AnchorHandoff { anchorHandoff }

	public init(first: UInt8, second: AnchorHandoff) throws {
		guard first == Self.discriminator else {
			throw LinearEncodingError.invalidPrefix
		}
		self.init(anchorHandoff: second)
	}
}

extension PrivateActiveAnchor {
	///Mint the anchor arm's establishment delegation. Called AFTER the session
	///layer's `receive` produced the return welcome (the welcome must exist to
	///be signed over) and BEFORE the session may emit — the session layer
	///refuses to staple until the resulting envelope installs.
	public func createPQAnchorEstablishmentHandoff(
		agentUpdate: AgentUpdate,
		newAgent: AgentPrivateKey,
		from retiredAgent: PrivateAnchorAgent,
		welcome: Data
	) throws -> PQAnchorEstablishmentHandoff {
		//an empty welcome can never be joined; reject locally before signing
		guard !welcome.isEmpty else {
			throw LinearEncodingError.requiredValueMissing
		}
		let context = PQEstablishmentBinding.context(welcome: welcome)
		return .init(
			anchorHandoff: try createNewAgentHandoff(
				agentUpdate: agentUpdate,
				newAgent: newAgent,
				from: retiredAgent,
				groupContext: context,
				mlsUpdateDigest: context
			)
		)
	}
}
