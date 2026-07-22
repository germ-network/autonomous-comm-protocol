# @germ-network/autonomous-comm-protocol

## 1.11.0

### Minor Changes

- [#42](https://github.com/germ-network/autonomous-comm-protocol/pull/42) [`28b7337`](https://github.com/germ-network/autonomous-comm-protocol/commit/28b733762b12d598d80f2d4df6631d818e4892a3) Thanks [@germ-mark](https://github.com/germ-mark)! - Add read capability for a `jpeg = 2` case on `ImageType`, plus `ImageType.detect(from:)` magic-byte classification (JXL codestream, JXL container, JPEG). No writer emits `.jpeg` yet: senders without a JPEG XL encoder (the App Clip) keep labeling JPEG bytes `.jpegXL` so that deployed clients — which fail the whole signed `CoreIdentity` parse on an unknown discriminant — are unaffected. Consumers should classify by bytes via `detect(from:)`, not the wire label.

## 1.10.0

### Minor Changes

- [#40](https://github.com/germ-network/autonomous-comm-protocol/pull/40) [`375788f`](https://github.com/germ-network/autonomous-comm-protocol/commit/375788f23f4a2f413a416a1564a234ddc7a390e8) Thanks [@germ-mark](https://github.com/germ-mark)! - Add opaque-digest handoff bodies (v2), with corrected discriminators.

  `createNewAgentHandoff` and `PublicAnchorAgent.verify(anchorHandoff:…)` gain
  overloads taking `groupContext`/`mlsUpdateDigest` as `Data` instead of
  `TypedDigest`. The new v2 signature bodies commit to those bytes as length-framed
  values and never interpret them.

  The motivation is ownership. A digest's algorithm is a facet of the MLS backend's
  cipher suite, so requiring a `TypedDigest` meant the backend could not adopt a new
  suite until this package shipped a matching `DigestTypes` case — a release
  dependency in the wrong direction. Committing to opaque bytes removes it: the
  caller's own self-describing encoding travels inside the value, so cross-era
  signatures stay unambiguous without this package knowing the eras.

  This is safe because a verifier never parses a digest out of a handoff — it
  rebuilds the signature body from its own locally derived reference digest and
  checks the signature against that. Agreement on the algorithm is enforced where
  the session is established, not here.

  **Nothing existing changes.** The typed overloads, the v1 bodies, and their
  discriminators are untouched, so every already-issued handoff keeps verifying.
  v1 and v2 are mutually unverifiable by construction (distinct discriminators),
  which is pinned by tests in both directions.

  **Discriminator note.** v1's `ActiveAgentBody` and `RetiredAgentBody` carry each
  other's names. That is a labeling bug, not a security one — domain separation
  needs the committed strings to be distinct, not correctly named, and they are —
  but it is now frozen and commented as such, because renaming in place would
  silently fail verification for every live relationship. The v2 bodies carry the
  corrected names, `.v2`-suffixed: the plain corrected strings are unavailable
  precisely because v1 has them live on the opposite structs. A test asserts all six
  are pairwise distinct.

## 1.9.0

### Minor Changes

- [#38](https://github.com/germ-network/autonomous-comm-protocol/pull/38) [`f00afe3`](https://github.com/germ-network/autonomous-comm-protocol/commit/f00afe37ad635f365a74ced3f268297243566b85) Thanks [@germ-mark](https://github.com/germ-mark)! - Add a `CommProposal.pqCardUpgrade(SignedObject<PQCardUpgrade>)` case (`ProposalType = 5`), the in-band carrier for upgrading an existing classical card relationship to a post-quantum (TwoMLSPQ) session over the relationship's own established session — see the app's `pq-card-in-session-negotiation.md`.

  `PQCardUpgrade` pairs the displaced `.sameAgent` round's `AgentUpdate` (so that frame still delivers its version and addresses) with a `Payload` of `.keyPackage(Data)` (offer), `.welcome(Data)` (reply), or `.decline(UInt8)` (terminal). It is signed by the established agent over the same `updateMessage + context` binding as `.sameAgent` (`proposePQCardUpgrade` / `AgentPublicKey.validate(signedUpgrade:for:context:)`), so the offer/welcome is bound to the MLS proposal that carries it. `ValidatedForCard` gains a `.pqCardUpgrade(PQCardUpgrade)` case; the anchor validation surface keeps rejecting it via its existing `default`.

  Strictly additive on the wire. Because the new `ProposalType` tag drops the whole message on a pre-1.9.0 (`LinearEnum`-strict) peer, the case must only ever be emitted to a peer already confirmed PQ-capable (`AgentUpdate.isPQCapable`, observed inbound) — the capability gate lives in the app. No changes to existing cases; the full suite plus new `PQCardUpgradeTests` pass.

## 1.8.0

### Minor Changes

- [#36](https://github.com/germ-network/autonomous-comm-protocol/pull/36) [`129d6f7`](https://github.com/germ-network/autonomous-comm-protocol/commit/129d6f79cb6cb2841ea100c8e0bf02f8a880a4e6) Thanks [@germ-mark](https://github.com/germ-mark)! - Drop the shared `groupId` from the PQ card establishment reply. `PQAppWelcome.Content` no longer carries a `DataIdentifier groupId` (Quintuple → Quad), and the introduction's signature context switches from `.reply`/`.welcome(groupId:)` to a new seedless `AgentTypes.pqCardEstablishment(remoteAgentId:)` that binds only the answered peer agent (the cross-invitation anti-splice), not a per-session seed.

  Rationale: a PQ card session's identity is the crate's LOCAL send-group id (each endpoint keys its own), not a shared, initiator-chosen id transmitted on the wire and used as a shared at-rest record key. The session↔welcome↔identity weld is already the born-dedicated establishment handoff over `sha256(welcome)`, so the seed==groupId cross-check the introduction used to carry is redundant (the agent-signed `Content` plus the handoff pin the establishment).

  Wire-breaking for the PQ card reply only; classical `AppWelcome` is unchanged. Adopters must regenerate PQ card invitations/establishments (pre-ship). No new errors. Verified: the full CommProtocol suite passes, including the recipient-binding anti-splice test (`testWrongRecipientAgentFailsValidation`), which confirms the peer-agent binding survives the seed removal.

## 1.7.0

### Minor Changes

- [#34](https://github.com/germ-network/autonomous-comm-protocol/pull/34) [`4df47c9`](https://github.com/germ-network/autonomous-comm-protocol/commit/4df47c92cc9886508ed8943a7bb70b2f4dfaafe7) Thanks [@germ-mark](https://github.com/germ-mark)! - Add the born-dedicated establishment delegation (TwoMLSPQ contract 26): `PQCardEstablishmentHandoff` and `PQAnchorEstablishmentHandoff` carry the identity-signed handoff artifact on the establishment staple, next to the unmodified spec-conformant return welcome, with every to-be-signed slot derived from the welcome bytes (`PQEstablishmentBinding`) so the delegation binds the exact group being joined and cannot cross-validate as a steady-state rotation handoff. Create via `AgentPrivateKey.completePQCardEstablishment` / `PrivateActiveAnchor.createPQAnchorEstablishmentHandoff`.

## 1.6.1

### Patch Changes

- [#32](https://github.com/germ-network/autonomous-comm-protocol/pull/32) [`870dab4`](https://github.com/germ-network/autonomous-comm-protocol/commit/870dab4502e80298defaebe39aaa642a5b2def67) Thanks [@germ-mark](https://github.com/germ-mark)! - Fix a cross-route parsing confusion in the PQ establishment welcomes
  (`PQAppWelcome` / `PQAnchorWelcome`, shipped in 1.6.0). Their domain separation
  from the classical `AppWelcome` / `AnchorWelcome` rested on the signed content's
  fifth element diverging in layout, which in turn depended on the signing-key and
  digest prefix enums keeping disjoint raw values. A crafted 128-byte classical
  key package round-tripped byte-identically through the PQ parse, so a classical
  welcome's own agent signature also validated it as a PQ welcome.

  `PQEstablishmentKeyMaterial` now leads with a checked reserved `0x00` byte — the
  one length prefix a classical key-package `Data` field can never carry — so both
  cross-parse directions reject deterministically at decode, independent of any
  enum raw values. This changes the PQ welcome wire format (the classical welcomes
  are byte-for-byte unchanged); regenerate any PQ welcomes serialized under 1.6.0.

## 1.6.0

### Minor Changes

- [#30](https://github.com/germ-network/autonomous-comm-protocol/pull/30) [`baeb158`](https://github.com/germ-network/autonomous-comm-protocol/commit/baeb158c7e24765889e106cb47d65892a3753e1d) Thanks [@germ-mark](https://github.com/germ-mark)! - Make wire-bound Dates round-trip to exact equality. The wire format stores
  `timeIntervalSince1970.bitPattern`, but `Date` equates on
  `timeIntervalSinceReferenceDate`, and the epoch conversion in Double rounds
  away the low mantissa bit for ~half of current-era clock values — so
  `parse(wireFormat) == original` was a coin flip for any Date stamped `.now`,
  and whole-struct equality across a wire round trip flaked per-run (bit
  PQAppWelcomeTests on PR [#29](https://github.com/germ-network/autonomous-comm-protocol/issues/29)).

  Adds `WireDate` — a Date pre-rounded to the wire grid at construction
  (moving the instant by at most 2⁻²³ s ≈ 120 ns) — as the field type of
  every Date-carrying wire struct (`sentTime`, succession proof dates,
  `NewAgentData.expiration`), and removes `Date`'s own LinearEncodable
  conformance, so a raw-Date wire field no longer compiles. Wire bytes are
  unchanged and round trips are exact by construction; only in-memory sub-µs
  noise is removed. Source-breaking for field readers: take `.date` off a
  `WireDate` (Date-taking convenience inits are unchanged, e.g.
  `NewAgentData`'s). `Date.wireNormalized` exposes the same rounding for
  comparing a caller-held Date against a round-tripped `.date`.

- [#29](https://github.com/germ-network/autonomous-comm-protocol/pull/29) [`19f73c3`](https://github.com/germ-network/autonomous-comm-protocol/commit/19f73c3bafe4c40f53cb6e4acf5042858ce136f8) Thanks [@germ-mark](https://github.com/germ-mark)! - Add `PQAnchorWelcome` / `PQAppWelcome`: parallel establishment-reply structs for
  the PQ (TwoMLSPQ v20) path. The classical `AnchorWelcome` / `AppWelcome` stay
  live unchanged — routing discriminates (the PQ reply only ever answers a PQ
  hello), so there is no version field.

  Both carry the new `PQEstablishmentKeyMaterial` pair inside the signed body:
  the replier's CLASSICAL return key package plus a `TypedDigest` commitment
  (SHA-256) to the A.4 bootstrap PQ key package, binding the deferred PQ key
  material to the sender's identity root. New signature discriminators
  ("PQAnchorReply.\*") domain-separate the anchor arm from the classical welcome;
  the card arm's content layout diverges structurally at the fifth element.

  New API: `PrivateActiveAnchor.createPQAnchorWelcome`,
  `AnchorPublicKey.verify(pqReply:recipient:)`,
  `AgentPrivateKey.createPQAppWelcome`, `PQAppWelcome.validated(myAgent:)`,
  plus `PQAppWelcome.mock` / `PQEstablishmentKeyMaterial.mock` in
  CommProtocolMocks.

## 1.5.0

### Minor Changes

- [#27](https://github.com/germ-network/autonomous-comm-protocol/pull/27) [`482a619`](https://github.com/germ-network/autonomous-comm-protocol/commit/482a619ee821a660938b57436ede328471070364) Thanks [@germ-mark](https://github.com/germ-mark)! - Add `IdentityPrivateKey.createAgentDelegate(for:context:)` — delegate this
  identity to an agent key the caller already holds, rather than minting one. The
  delegate binds only the agent's public key, so the caller keeps the private half.

  Needed when the agent key must be chosen before the delegation context is known:
  a post-quantum card session's receiver picks its new agent key up front (the
  session's `newClientId`), then learns the session proposal context only after the
  establishment handshake — the same-identity mirror of how an anchor's
  `createNewAgentHandoff` already accepts a pre-minted agent. The existing
  `createAgentDelegate(context:)` now routes through the new variant; behavior
  unchanged.

## 1.4.0

### Minor Changes

- [#24](https://github.com/germ-network/autonomous-comm-protocol/pull/24) [`d65f4ad`](https://github.com/germ-network/autonomous-comm-protocol/commit/d65f4ad7530183b565b92081ceeb3553f5d7035d) Thanks [@germ-mark](https://github.com/germ-mark)! - Carry a post-quantum (TwoMLSPQ) key package in the card offer as a legacy shim. `MLSIntroduction.postQuantumShim(kemPublicKeyData:encodedKeyPackage:)` builds an entry that is wire-indistinguishable from a classical one — the suite and kem key stay classical and the self-contained PQ key package rides in `encodedKeyPackage` — so already-deployed parsers accept a card that offers both classical and PQ. PQ-capable consumers detect the PQ entry by parsing its key package; publishers keep the classical entry at index 0. The card wire format is unchanged (byte-identical, golden-pinned); an honest, suite-typed card format is left for a future replacement.

- [#25](https://github.com/germ-network/autonomous-comm-protocol/pull/25) [`4db3b73`](https://github.com/germ-network/autonomous-comm-protocol/commit/4db3b739b0bd608e50266af096e2de42434f2e30) Thanks [@germ-mark](https://github.com/germ-mark)! - Domain-separate the `AgentHandoff` new-agent signing body, gated on
  `AgentUpdate.version`. Agents at/above `AgentUpdate.pqDomainSeparationVersion`
  prepend a discriminator; classical (sub-threshold) agents keep the pre-separation
  body byte-for-byte. Both signer and verifier derive the choice from the version
  inside the signed body, so it is deterministic and needs no separate rollout — it
  shadows the PQ capability version bump. Inert until an app declares a
  ≥-threshold agent version.

  Also add `AgentUpdate.pqCapableVersion` (2.3.0), the PQ parse-capability tier that
  sits below `pqDomainSeparationVersion`: an agent at this version advertises PQ
  capability while its handoff bodies stay undiscriminated, so the classical wire
  format is unchanged. It is `public` so the app imports the same constant.

- [#23](https://github.com/germ-network/autonomous-comm-protocol/pull/23) [`c3280ed`](https://github.com/germ-network/autonomous-comm-protocol/commit/c3280ed68d9ab36e2a92f2dda8487699a2095fe2) Thanks [@germ-mark](https://github.com/germ-mark)! - Hardening from the security/functional review:

  - Move mock factories out of the production library into a new `CommProtocolMocks`
    product; consumers import it explicitly.
  - Throw (rather than silently drop entries) when anchor archive/proof-history
    decoding fails.
  - Parse fixed-width integers with `loadUnaligned` instead of the alignment-sensitive
    `load(as:)`.
  - Add `IdentityMutableData.supersedes(_:)` / `validateSupersedes(_:)` (and a
    `ProtocolError.staleUpdate` case) so callers can reject replayed or rolled-back
    mutable data by counter.

### Patch Changes

- [#22](https://github.com/germ-network/autonomous-comm-protocol/pull/22) [`4eafc78`](https://github.com/germ-network/autonomous-comm-protocol/commit/4eafc782dbc2b5d2e810e8da444ecaeb4259f4ab) Thanks [@germ-mark](https://github.com/germ-mark)! - Fix anchor-key rotation continuity. `verify(successionFrom:)` verified succession
  proofs under the successor key instead of the predecessor key that signed them, so
  any Hello carrying a proof (i.e. from a rotated anchor) failed with
  `.authenticationError`. Also fix `PrivateActiveAnchor.handOff()` truncating proof
  history to a single hop, which dropped continuity back to the original key across
  repeated rotations.

## 1.3.0

### Minor Changes

- [#19](https://github.com/germ-network/autonomous-comm-protocol/pull/19) [`d0fe312`](https://github.com/germ-network/autonomous-comm-protocol/commit/d0fe312e1456d3edccc5e848fdfb37488b2d4cee) Thanks [@germ-mark](https://github.com/germ-mark)! - fix key type error

## 1.2.2

### Patch Changes

- [#17](https://github.com/germ-network/autonomous-comm-protocol/pull/17) [`a18f62d`](https://github.com/germ-network/autonomous-comm-protocol/commit/a18f62d9778427550c9b5be42daea5a810d044b7) Thanks [@germ-mark](https://github.com/germ-mark)! - use independent base64 dependency

## 1.2.1

### Patch Changes

- [#15](https://github.com/germ-network/autonomous-comm-protocol/pull/15) [`bf3eec4`](https://github.com/germ-network/autonomous-comm-protocol/commit/bf3eec442a01b1a1707374ad2bbeaf8db22c62b5) Thanks [@germ-mark](https://github.com/germ-mark)! - adopt changes in atprotoTypes, and moving convenience methods such as utf8Data into GermConvenience

## 1.2.0

### Minor Changes

- [#12](https://github.com/germ-network/autonomous-comm-protocol/pull/12) [`9f10b3f`](https://github.com/germ-network/autonomous-comm-protocol/commit/9f10b3fb2075ed208b2ab9bf5fd21ac002bc0c9a) Thanks [@germ-mark](https://github.com/germ-mark)! - Remove AtprotoDID and instead use the type defined in https://github.com/germ-network/AtprotoTypes
