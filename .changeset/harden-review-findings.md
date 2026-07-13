---
"@germ-network/autonomous-comm-protocol": minor
---

Hardening from the security/functional review:

- Move mock factories out of the production library into a new `CommProtocolMocks`
  product; consumers import it explicitly.
- Throw (rather than silently drop entries) when anchor archive/proof-history
  decoding fails.
- Parse fixed-width integers with `loadUnaligned` instead of the alignment-sensitive
  `load(as:)`.
- Add `IdentityMutableData.supersedes(_:)` / `validateSupersedes(_:)` (and a
  `ProtocolError.staleUpdate` case) so callers can reject replayed or rolled-back
  mutable data by counter.
