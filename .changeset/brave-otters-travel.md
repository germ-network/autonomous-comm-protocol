---
"@germ-network/autonomous-comm-protocol": patch
---

Depend on swift-crypto and import Crypto instead of CryptoKit, so the package
builds on Linux and Android. On Apple platforms swift-crypto delegates to
CryptoKit, so behavior is unchanged. Raises the AtprotoTypes floor to 0.5.0,
the first release that builds on those platforms.
