---
"@germ-network/autonomous-comm-protocol": patch
---

Pin `swift-cbor` to `from: "0.1.0"` instead of a revision. The revision pin
predates swift-cbor's 0.1.0 release; confirmed the pinned commit
(`8d9b9c2`, the `deterministicCbor` option) is an ancestor of 0.1.0's tagged
commit, so this is a no-op for the code actually built. It matters because a
stable-tagged package (this one, as of `v1.12.0`) cannot depend on a
revision-pinned package — SwiftPM refuses to resolve it for any downstream
consumer pinning this package by version, which blocked `germ-service-client`
picking up `v1.12.0`.
