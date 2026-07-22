---
"@germ-network/autonomous-comm-protocol": minor
---

Add read capability for a `jpeg = 2` case on `ImageType`, plus `ImageType.detect(from:)` magic-byte classification (JXL codestream, JXL container, JPEG). No writer emits `.jpeg` yet: senders without a JPEG XL encoder (the App Clip) keep labeling JPEG bytes `.jpegXL` so that deployed clients — which fail the whole signed `CoreIdentity` parse on an unknown discriminant — are unaffected. Consumers should classify by bytes via `detect(from:)`, not the wire label.
