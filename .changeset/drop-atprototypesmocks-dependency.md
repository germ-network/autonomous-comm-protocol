---
"@germ-network/autonomous-comm-protocol": patch
---

Remove the unused `AtprotoTypesMocks` dependency from the `CommProtocol` target.

No source in `CommProtocol` imports it — only `CommProtocolTests` does, so the
dependency moves to the test target. `CommProtocol` previously pulled
`AtprotoTypesMocks` (and its `Mockable` dependency) into every consumer's link
closure, including the CoreAppLogic Android release `.so`.
