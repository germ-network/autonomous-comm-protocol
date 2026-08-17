---
"@germ-network/autonomous-comm-protocol": patch
---

Adopt swift-bases 0.3.0's throwing `Data(base64URLEncoded:)` in `MailboxGrant.mailboxGrant`. No behavior change — a decode failure still yields `nil` from that computed property — but this was a source break for anyone whose resolved dependency graph floats past swift-bases 0.2.1.
