# Identity, the master key and the server name

Status: **approved** 2026-11-12 (drafted by the consultant session, 2026-11-10), from the format-freeze
review of `origin/wipe-2`. Two decisions the main session proposed, pending
the user: the account authority becomes random and stored, and
self-statements bind the account id, not the server's name. Both change
persistent bytes, so both land before the wipe.

## 1. Today

- `kutup-crypto/src/identity.rs:38` derives three keys from the master key
  (MK): the account authority, the Drive X-Wing key and the Drive
  share-signing key. The incarnation id is the hash of the authority's public
  key (`:104`).
- So a new MK is a new authority and a new incarnation (the crate's own test:
  `a_new_master_key_is_a_new_incarnation`). Everything bound to either
  changes: named shares, profile-key envelopes, collection epoch chains
  (`collection_epoch.rs:162` checks one authority), Chat backup objects
  (`chat_backup.rs:136,195`), organization certificates, and pins, which
  treat a new incarnation as a wipe.
- `AccountRef::bytes()` (`account_ref.rs:66`) is the server's DNS name and the
  account id. It is signed or bound in the manifest and identity binding,
  safety numbers, the profile envelope, group pseudonyms, Drive shares and
  the Drive key binding. Group ids bind the home server's name too
  (`chat_group.rs:78-98`). A server can never change its domain.

Both break the standing rule: a changeable value (the MK after a rotation,
a DNS name) is bound into cryptography.

## 2. What the references do

Paths are in `kutup-references`. I located these files but did not re-read
them for this note; check a line before quoting it.

- **Signal.** The identity key pair is random and stored. A linked device
  receives it in the provisioning message
  (`Signal-Desktop/ts/textsecure/ProvisioningCipher.node.ts`,
  `Provisioner.preload.ts`). The master key and the storage-service key come
  from the account entropy pool (`Signal-Desktop/ts/Crypto.node.ts`,
  `ts/services/storage.preload.ts`) and can change without touching the
  identity. The server keys an identity by ACI
  (`Signal-Server/.../storage/Account.java`); a phone number change keeps the
  ACI and identity (`ChangeNumberManager.java`).
- **Proton.** User and address keys are random. A password change re-encrypts
  them and changes nothing a contact sees
  (`WebClients/packages/shared/lib/keys/changePassword.ts`). Only a reset
  makes new keys (`resetKeys.ts`). Address keys are locked by a token under
  the user key (`addressKeys.ts`), so the two layers rotate apart.

## 3. Proposal: the key hierarchy

```text
MK (random, generation mk_gen, wrapped by password and recovery)
 ├─ seals account records (KUTPAR1, header names mk_gen)
 ├─ derived, private to the account, never seen by a peer:
 │    record object-id key, account-head keys, mail-search store key
 └─ wraps, as account records (random and stored):
      identity root  (identity generation id_gen)
        ├─ authority signing key        → incarnation id, manifest, pins
        ├─ Drive X-Wing key             → shares sealed to the account
        └─ Drive share-signing key      → shares and block manifests
      Drive root key                    → own collection keys, link owner copies
      group pseudonym root              → per-group pseudonyms
      call-link root                    → call-link owner secrets
      (already stored: libsignal identity, mail and calendar keys,
       vault secrets, backup root, organization keys)
```

- **Rule (W6 §1, sharpened):** a key a peer verifies or seals to, or that
  roots long-lived data, is random and stored. Only keys that are private to
  the account and cheap to re-derive stay derived from the MK.
- **Identity root:** one 32-byte secret; the three identity keys derive from
  it with today's labels. A new account-record purpose `IdentityRoot` holds
  it, with `id_gen` in the plaintext. The incarnation id stays the hash of
  the authority's public key: it now changes only at a reset or an identity
  rotation.
- **Drive root key:** today's own collection keys are sealed under the MK
  itself (the CLI's `decrypt_collection_key(col, &master_key)`). They move
  under a stored Drive root key, so an MK rotation re-wraps one record
  instead of every folder. `DriveEnvelopeV1` then needs no master-key
  generation. If the Drive root itself rotates, purpose 1 and purpose 9
  carry its generation in the revision slot (purpose 9's epoch and both
  revisions are fixed at 1 today).

## 4. Two rotations

- **MK rotation** (a password or recovery phrase exposed, an organization
  taking or releasing escrow, routine): new MK, `mk_gen + 1`, the old MK kept
  in a keyring record under the new one. Records are re-sealed lazily; the
  identity does not change; no contact sees anything.
- **Identity rotation** (a device lost or stolen, since every device holds
  the identity root): a new identity root, `id_gen + 1`, and always a new MK
  as well. Contacts see a safety-number change, as on Signal. Continuity for
  the account itself comes from a succession statement: the new authority's
  public key signed by the old authority and the reverse, kept in the
  manifest history. A thief holds the old authority too, so the statement
  proves nothing to a contact on its own; its use is that the owner's other
  devices and old signatures (epoch chains, block manifests) stay verifiable
  under "an authority of this account at the time".

## 5. Rotation checklist

W6's list (`docs/plans/w6-key-hierarchy.md`, "Rotation checklist") stays.
Add:

MK rotation:
- the `IdentityRoot`, Drive root, pseudonym root and call-link root records:
  re-wrapped at once, not lazily;
- records with a hashed object id get new ids (W6 already says so); with a
  stored object-id key instead of a derived one this step disappears, which
  is worth doing now;
- `mail_search.rs:114` takes the real generation, not `FIRST`;
- the server's fake recovery envelope shows a plausible generation.

Identity rotation, everything above and:
- account manifest: new authority, the succession statement, new Drive key
  binding (its `epoch` field exists for this; pins must record the highest
  seen);
- collection epoch chains: each owned folder gets a new epoch signed by the
  new authority; `collection_keyring::unlock` accepts older statements under
  an authority the manifest history lists;
- named shares, file shares and profile-key envelopes to the account: senders
  re-seal to the new X-Wing key when they next see the manifest; the old key
  stays readable from the kept identity root;
- block manifests: the signer field gains the signing key's id (§7), so old
  manifests verify against the right key;
- Chat: a new libsignal identity is a separate, existing flow; the backup
  binds only `backup_incarnation_id`, not the account incarnation;
- group pseudonyms and call links: unchanged, since their roots are stored;
- organizations: certificates re-signed, escrow re-sealed (W6 already lists
  both).

## 6. The server name leaves the cryptography

- **Self-statements bind the account id alone**, 16 bytes: the manifest and
  identity binding, safety numbers, the profile envelope, the Drive key
  binding, group pseudonym bindings. Statements between two people (named
  shares, profile-key shares) bind the two account ids and the two
  incarnations.
- **`AccountRef` stays as the routing address** `(server, account id)`: in
  JSON, in federation requests, as the key of local stores, pins and the
  libsignal address name. These are lookups, not signed bytes; a server
  rename is then a re-keying of local rows.
- **Collisions.** Account ids are minted by each server, so a hostile server
  can mint one equal to a victim's. This gains nothing cryptographically:
  every statement is checked under the authority pinned for the routing
  address, and the incarnation (the authority's hash) is still bound. The
  rule that makes it safe: a client never looks anything up by account id
  alone.
- **Group ids** bind the home's identity-document hash and sequence, which
  already identify the home by its key; drop the name from the digest.
- **Pins** stay keyed by `(server, account id)` and hold the authority. Two
  new signed statements move them: an account's "my home is now S", signed
  by its authority, and a server's "my name is now N", in its federation
  identity chain. Neither is built now; the formats only have to stop
  preventing them.
- **Federation** keeps routing by name and authenticating by the server's
  identity chain. Nothing changes on the wire except the signed bytes above.

## 7. One related format change

The block manifest's signer is a kind byte and a bare account id
(`blocks.rs:303`). Make it kind 2: account id, incarnation id (32 bytes).
The reader then knows which authority's Drive signing key to check, across
resets, rotations and servers.

## 8. Order

1. `identity.rs`: identity root in, MK derivation out; the `IdentityRoot`,
   Drive root, pseudonym root and call-link root purposes (second session,
   with W1/W6). Vectors.
2. `AccountRef::bytes()` splits into `id_bytes()` (signed) and the routing
   form; every signer and verifier switches; safety numbers, pins and
   profile vectors regenerate (second session, W5).
3. Drive: collection keys and link owner copies under the Drive root; the
   signer kind 2; group id digest (main session, in the block slices).
4. The rotation exercise: MK rotation end to end in Rust with vectors and one
   live test, no UI. Identity rotation as a written walk-through against the
   checklist, built after the wipe.
5. Docs: `v1-format-inventory.md`, `w6-key-hierarchy.md`, the threat models.

## Open questions

1. Is identity rotation without a reset wanted at all before v1, or is
   "reset the account" enough for a stolen device in the beta? The formats
   above allow either.
2. Object-id key: stored (ids survive an MK rotation) or derived (W6's
   current plan, ids move)? The recommendation is stored.
3. Should the Drive X-Wing key and the share-signing key rotate apart from
   the authority? Not now; one identity root is simpler and matches Signal.

## Decisions (2026-11-12)

- The authority is random and stored under the master key generation; self-statements bind the account id, not the server's name (the user did not object to the main session's proposal of 2026-11-10).
- The formats (stored identity root, stored object-id key, the `AccountRef` split) land before the wipe; the master-key rotation exercise proves them before the freeze. A full identity rotation flow (UI, safety-number change, succession statement) is built after the wipe.
