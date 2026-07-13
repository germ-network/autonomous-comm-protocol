# @germ-network/autonomous-comm-protocol

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
