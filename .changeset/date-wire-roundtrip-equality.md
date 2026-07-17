---
"@germ-network/autonomous-comm-protocol": minor
---

Make wire-bound Dates round-trip to exact equality. The wire format stores
`timeIntervalSince1970.bitPattern`, but `Date` equates on
`timeIntervalSinceReferenceDate`, and the epoch conversion in Double rounds
away the low mantissa bit for ~half of current-era clock values — so
`parse(wireFormat) == original` was a coin flip for any Date stamped `.now`,
and whole-struct equality across a wire round trip flaked per-run (bit
PQAppWelcomeTests on PR #29).

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
