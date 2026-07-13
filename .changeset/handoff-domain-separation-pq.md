---
"@germ-network/autonomous-comm-protocol": minor
---

Domain-separate the `AgentHandoff` new-agent signing body, gated on
`AgentUpdate.version`. Agents at/above `AgentUpdate.pqDomainSeparationVersion`
prepend a discriminator; classical (sub-threshold) agents keep the pre-separation
body byte-for-byte. Both signer and verifier derive the choice from the version
inside the signed body, so it is deterministic and needs no separate rollout — it
shadows the PQ capability version bump. Inert until an app declares a
≥-threshold agent version.
