---
"@germ-network/autonomous-comm-protocol": minor
---

`MailboxGrant` carries an optional `"v"` put-scheme version (absent = legacy, 2 = Germ PMR) and derives its address and put tag per scheme. `AgentUpdateV2` skips a grant it can't read instead of failing, and its signature still verifies.
