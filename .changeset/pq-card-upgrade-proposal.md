---
"@germ-network/autonomous-comm-protocol": minor
---

Add a `CommProposal.pqCardUpgrade(SignedObject<PQCardUpgrade>)` case (`ProposalType = 5`), the in-band carrier for upgrading an existing classical card relationship to a post-quantum (TwoMLSPQ) session over the relationship's own established session — see the app's `pq-card-in-session-negotiation.md`.

`PQCardUpgrade` pairs the displaced `.sameAgent` round's `AgentUpdate` (so that frame still delivers its version and addresses) with a `Payload` of `.keyPackage(Data)` (offer), `.welcome(Data)` (reply), or `.decline(UInt8)` (terminal). It is signed by the established agent over the same `updateMessage + context` binding as `.sameAgent` (`proposePQCardUpgrade` / `AgentPublicKey.validate(signedUpgrade:for:context:)`), so the offer/welcome is bound to the MLS proposal that carries it. `ValidatedForCard` gains a `.pqCardUpgrade(PQCardUpgrade)` case; the anchor validation surface keeps rejecting it via its existing `default`.

Strictly additive on the wire. Because the new `ProposalType` tag drops the whole message on a pre-1.9.0 (`LinearEnum`-strict) peer, the case must only ever be emitted to a peer already confirmed PQ-capable (`AgentUpdate.isPQCapable`, observed inbound) — the capability gate lives in the app. No changes to existing cases; the full suite plus new `PQCardUpgradeTests` pass.
