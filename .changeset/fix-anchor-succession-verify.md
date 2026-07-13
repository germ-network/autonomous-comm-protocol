---
"@germ-network/autonomous-comm-protocol": patch
---

Fix anchor-key rotation continuity. `verify(successionFrom:)` verified succession
proofs under the successor key instead of the predecessor key that signed them, so
any Hello carrying a proof (i.e. from a rotated anchor) failed with
`.authenticationError`. Also fix `PrivateActiveAnchor.handOff()` truncating proof
history to a single hop, which dropped continuity back to the original key across
repeated rotations.
