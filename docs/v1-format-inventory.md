# V1 cryptographic format inventory

**Status:** normative pre-tag cutover inventory

This inventory names every persistent or federated ciphertext family that the
V1 cutover must replace or freeze. Kutup is preproduction, so legacy rows,
development object storage and browser databases are recreated rather than
dual-written. This destructive rule expires at the first stable `v*` tag.

| Purpose | Pre-V1 shape | V1 owner and format |
|---|---|---|
| Master-key password wrap | XSalsa20 secretbox plus separate nonce; implicit Argon parameters | `AccountProtectionSuiteId` plus `AccountProtectionEnvelopeV1`, XChaCha, persisted Argon2id parameters |
| Master-key recovery wrap | XSalsa20 secretbox under random recovery entropy | `AccountProtectionEnvelopeV1` with recovery purpose and XChaCha |
| Account sharing private key | XSalsa20 secretbox; public X25519 key stored separately | Account-scoped Drive keys in `AccountManifestV1`; private material wrapped by a typed account envelope |
| Collection name/key | Separate ciphertext/nonce columns with implicit secretbox | `DriveEnvelopeV1`, purpose-tagged and bound to collection, owner and epoch |
| File metadata/key | Separate ciphertext/nonce columns with implicit secretbox | `DriveEnvelopeV1`, bound to file, collection, revision and epoch |
| File blob | Raw secretstream header/chunks | `DriveObjectSuiteId` header plus existing 5 MiB secretstream framing bound to file, collection and epoch |
| Local/federated named share | Anonymous `crypto_box_seal` bytes | `NamedShareEnvelopeV1`, X25519 HPKE plus manifest-bound Ed25519 sender signature |
| Public-link collection wrap | Secretbox under link key | Purpose-tagged `DriveEnvelopeV1`; link capability remains a separate authorization mechanism |
| Collaborative frame | XChaCha frame with `doc_key_id`, device and sequence | `CollabFrameSuiteId`; epoch reaches the KDF and authenticated header; purpose-specific content key |
| Whiteboard asset | XChaCha with asset AAD | `DriveEnvelopeV1` asset purpose and purpose-specific subkey |
| Encrypted profile | AES-256-GCM nonce/ciphertext | `ProfileSuiteId` plus XChaCha `ProfileEnvelopeV1` |
| Direct Chat | `DirectChatSuiteId = 1`, libsignal bytes | Unchanged pinned libsignal suite |
| MLS group | MLS `0x0002`, P-256 control and delivery keys | MLS `0x0003`, X25519/ChaCha/Ed25519 throughout Kutup-owned bindings |
| Account device directory | Chat-only `DeviceManifest` plus global transparency proofs | One account-signed `AccountManifestV1` with complete device set, previous hash, history and durable peer pin |
| Broadcast post and grants | Absent | Typed broadcast policy, epoch, account/device grant, history grant and post structures |

Every V1 structure has a numeric typed suite, a fixed domain separator,
canonical big-endian length-prefixed signing/AAD encoding, deterministic test
vectors, strict byte limits and an explicit unknown-suite error. JSON is a
transport representation only and is never the signed encoding.

After V1, an old suite may remain readable while migration is active, but new
writes use exactly one locally allowed suite. Federation advertises supported
suites and returns `NoCommonSuite`; it never silently retries a legacy format.
