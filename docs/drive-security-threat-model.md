# Drive V1 security threat model

**Status:** normative for the pre-tag Drive cutover

## Assets and trust boundaries

- The account master key, account authority private key, Drive private keys,
  collection keys, file keys and plaintext exist only in clients.
- The server stores ciphertext, suite identifiers, object relationships,
  sizes, timing, access-control rows and opaque signed state.
- `AccountManifestV1` binds the account authority, account-scoped Drive keys
  and complete active device set. A face-to-face QR pins the authority and
  incarnation, not a particular device version.
- Collection owners sign the monotonic collection-key epoch. The server may
  relay or withhold it but cannot select a different current key.
- Federation authenticates servers and transport separately from the
  recipient account identity and share envelope.

## Threats and required results

| Threat | Required control and result |
|---|---|
| Server substitutes a share recipient key | Recipient key must be in the pinned or explicitly TOFU-accepted account manifest. A mismatch blocks sharing. |
| Server moves ciphertext between objects or revisions | Suite, purpose, canonical identifiers, epoch and revision are authenticated as AAD. Decryption fails without returning partial plaintext. |
| Server rolls back a collection after a member was removed | Owner-signed epoch chain and durable client pin reject rollback. Clients never write under an unverified pending epoch. |
| Removed member reads new content | Removal completes only after a new random collection key is distributed to remaining accounts and the signed epoch is committed. Previously learned plaintext/ciphertext cannot be revoked. |
| Offline writer uses a stale key | Upload and collaborative mutation carry the exact epoch; server and clients reject stale writes. There is no automatic legacy-key retry. |
| Named share is forged or redirected | HPKE ciphertext is signed by the sender's manifest-bound Drive signer and binds exact canonical sender, recipient, collection, epoch and suite. |
| Federation peer or network is unavailable | Retain established pins and readable cached data; block state-changing operations that require fresh identity/epoch evidence. |
| Account address is wiped and reused | Wipe terminates the old incarnation. Peers show a red identity reset and shares/groups do not transfer without explicit reauthorization. |
| Compromised client retains secrets | Device removal stops future authenticated service access and rotates affected future-access keys. It cannot remotely erase copied master keys or old plaintext. |
| Malformed or oversized ciphertext | Bounded strict parsers reject before allocation/decryption; fuzzing covers every public V1 structure. |
| Crash during epoch/share mutation | Manifest, epoch, member wraps, current state and audit event commit atomically; restart resumes an idempotent operation or retains the prior epoch. |

## Metadata not hidden in V1

Servers see accounts, collection/file relationships, ciphertext lengths,
access timing, storage size, federation domains and share membership. V1 does
not claim traffic-shape protection, ORAM, anonymous Drive sharing or
subscriber privacy from a user's own homeserver. The advanced fixed-cell
transport profile remains post-V1 work.

## Failure classes

Network unavailability may warn while retaining the last valid pin. Invalid
signature, account-authority replacement, manifest rollback/equivocation,
share substitution, epoch rollback or unknown suite blocks new writes and
shares durably. Recovery requires explicit identity acceptance or a valid
successor signed under the already pinned authority; a server assertion alone
never clears a cryptographic failure.
