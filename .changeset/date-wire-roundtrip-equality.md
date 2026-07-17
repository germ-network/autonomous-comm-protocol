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

Adds `Date.wireNormalized` — the same instant pre-rounded to the wire grid
(identical wire bytes, < 1 ulp adjustment) — and stamps it at every library
constructor that bakes a Date into a wire struct (`sentTime`, succession
proof dates). One parse is a fixed point, so normalized Dates survive any
number of round trips `==`-intact. Wire bytes are unchanged; only in-memory
sub-µs noise is removed. Callers supplying their own Dates (expirations)
should normalize likewise before comparing structs across a round trip.
