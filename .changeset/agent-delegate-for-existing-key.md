---
"@germ-network/autonomous-comm-protocol": minor
---

Add `IdentityPrivateKey.createAgentDelegate(for:context:)` — delegate this
identity to an agent key the caller already holds, rather than minting one. The
delegate binds only the agent's public key, so the caller keeps the private half.

Needed when the agent key must be chosen before the delegation context is known:
a post-quantum card session's receiver picks its new agent key up front (the
session's `newClientId`), then learns the session proposal context only after the
establishment handshake — the same-identity mirror of how an anchor's
`createNewAgentHandoff` already accepts a pre-minted agent. The existing
`createAgentDelegate(context:)` now routes through the new variant; behavior
unchanged.
