---
"@germ-network/comm-protocol": patch
---

Require swift-bases 0.3.0 in the manifest. `MailboxGrant` is written against 0.3.0's throwing `Data(base64URLEncoded:)`, but `Package.swift` still permitted 0.2.x — and consumers resolve from the manifest, not this package's `Package.resolved`, so the previous change expressed the adoption only locally.
