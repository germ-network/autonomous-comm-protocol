---
"@germ-network/autonomous-comm-protocol": minor
---

`ValidatedForAnchor` gains an `.agentUpdateV2` case (`CommProposal`'s tag 6 was
previously unhandled on the anchor path — `default: throw .unsupported`), mirroring
the existing card-side validation. `mailboxGrantVersion` moves `2.4.0` → `3.1.0`:
the original threshold assumed nothing had ever stamped a version at or above it
(the property that made `pqCapableVersion` = 2.3.0 sound), but
`pqDomainSeparationVersion` = 3.0.0 is already stamped by every PQ connection, so a
2.4.0 gate would have let an old PQ build believe it could parse tag 6 and then drop
the message. 3.1.0 clears every currently-stamped tier.
