# W1: one account-record envelope (build note)

Status: approved 2026-11-04 (decisions (a)-(e) below, all as recommended).
Slice 1 (the envelope) is merged; slice 2 (contact cards, mail names, identity
pins, and the key commitment) is in its PR.

Builds [wipe-unification.md](wipe-unification.md) W1 on what W6 already
shipped: `KUTPAE2` (now [account_record.rs](../../crates/kutup-crypto/src/account_record.rs))
has a purpose registry with a policy each (object, padding, revision), the
master-key generation, the key binding, a per-envelope HKDF key and the
server check `validate_for`. W1 makes it the one envelope for every
account-private sealed value and moves the other eleven formats onto it.
Needs the wipe (every format is persistent); goes into `wipe-2`.

## Today (surveyed on wipe-2, 2026-11-04)

| # | Value | Format | Binds | Size | Chain | Server reads |
|---|---|---|---|---|---|---|
| 1 | Contact card | `KUTCC2` | binding, UID (≤200 chars), rev | Bucket(256), ≤512 KiB | – | rev (+ a signed summary) |
| 2 | Mail folder/label/filter name | `KUTMN2` | binding, kind, id16, rev | Bucket(256), ≤400 B | – | rev (CAS) |
| 3 | Identity pins | `KUTIP3` | binding, rev; **no list id** | Bucket(256), ≤4 MiB | anchors in plaintext | rev (CAS) |
| 4 | Chat group list entry | `KUTPGL1` | binding, HMAC entry id, rev | fixed 4032 B | – | rev (CAS) |
| 5 | Chat contact list entry | `KUTPCC1` | binding, HMAC entry id, rev | fixed 2048 B | – | rev (CAS) |
| 6 | Photos library | `KUTPPL1` | incarnation, rev, previous; **no binding** | none, ≤4 MiB | header digest chain | header: incarnation, rev, previous |
| 7 | Chat attachment ledger | `KUTPCL1` | incarnation, entity16, rev, previous; **no binding** | none, ≤16 KiB | header digest chain | header: entity, incarnation, rev, previous |
| 8a | Account head | `KUTAH1` | binding, sequence | none, ≤16 KiB | `previous` in plaintext | sequence (CAS) |
| 8b | Local anchor (device only) | `KUTAL1` | binding, incarnation | none, ≤16 KiB | – | – |
| 9 | Revision-guard seen record (device only) | none, 48 B | HMAC entry; **no header** | fixed | – | – |
| 10 | Mail search store-key wrap (device only) | `KUTMSW1` | **nothing** | fixed 82 B | – | – |
| 11 | Joined meetings | none | **nothing** (constant AAD) | fixed 1024 B | – | length only |
| 12 | Chat profile key, own copy | `KUTPPE1` purpose 3 | address, version, rev, device | fixed | – | whole header |

None binds the master-key generation. Every one is "an AEAD under an MK
subkey with some AAD": the differences are what each forgot to bind.

## The envelope: `AccountRecordV1`

`KUTPAE2` becomes `KUTPAR1` (new magic, one suite, the purpose a `u16`).
The existing purposes (the password and recovery MK wraps, the Chat backup
root, mail address keys, Pass vault secrets, organization keys) move with
it, so there is one account-private format and one validator.

```text
magic      8   "KUTPAR1\0"
suite      u16 1 (W2's suite V1)
purpose    u16 closed registry (below)
mk_gen     u32 MasterKeyGeneration (W6)
binding    u16 len ‖ users.key_binding (canonical UUID)
object     u8 len ‖ object id      per policy: none, Raw(n) or Hashed
revision   u64                     mutable purposes only
previous   32                      chained purposes only (SHA-256 of the previous envelope; zero at revision 1)
nonce      24
length     u32
```

The whole header is the AAD and the HKDF info, as in `KUTPAE2` (salt
`kutup/account-record/v1\0`, info `kutup/account-record/key/v1\0 ‖ header
without nonce and length`), so every record has its own key and a moved,
replayed or relabelled record does not open.

Changes from `KUTPAE2`, each needed by a row above:

1. **A plaintext limit per purpose** (`PurposePolicy::max_len`) instead of one
   4096-byte cap: contact cards 512 KiB, pins and the Photos library 4 MiB.
   The envelope is one AEAD call, so size changes nothing else.
2. **Hashed objects** (`ObjectPolicy::Hashed`): a long or sensitive id (a
   contact UID, a group id, an account ref, a guard scope) is named by
   `HMAC(MK record-id key, purpose ‖ id)`, 32 bytes, as the chat lists
   already do. The plaintext carries the real id and the opener checks that
   it hashes to the header's object, as the contact list does today.
3. **A chain** (`PurposePolicy::chained`): `previous` in the header for
   Photos, the attachment ledger and the account head, so the server can
   enforce `revision = stored + 1` and `previous = stored digest` from the
   header alone (it does for Photos and the ledger today; for the head it
   checks only the sequence).
4. **The incarnation** stays where it is used: the Photos library and the
   ledger restart at revision 1 after an account reset, so their object is
   the incarnation (Photos) or the incarnation and entity together (ledger:
   `Hashed(incarnation ‖ entity)`, the server keeps the entity beside it).
   The binding, which they lacked, is now bound like everywhere else.

Padding stays per purpose (`Exact`, `Fixed(n)`, `Bucket(256)`), applied once
by the envelope.

**The per-purpose limits are the format's, not settings.** A purpose's
maximum length, padding and object size define what a valid record is, the
same on every server and in every client, so they are constants in the
registry and in the vectors. They are not site settings and must not become
one: a server with another limit would refuse records another client made.
What an account may store (its quota, how many contacts or pins) stays a
site setting, enforced where it is stored. The lists' "u16 length then zeros to a fixed total" becomes
`Fixed(n)`.

## Purposes

| Purpose | Object | Revision | Chain | Padding | Max |
|---|---|---|---|---|---|
| passwordMasterKey, recoveryMasterKey, chatBackupRoot | none | – | – | Exact(32) | 32 |
| mailAddressPrivateKey | none | – | – | Bucket(256) | 4 KiB |
| passVaultSecret | Raw(16) file id | yes | – | Fixed | as today |
| organizationPrivateKey | Raw(32) key id | – | – | Exact(32) | 32 |
| contactCard | Hashed(UID) | yes | – | Bucket(256) | 512 KiB |
| mailName | Raw(17) kind ‖ id | yes | – | Bucket(256) | 400 B |
| identityPins | Raw(16) list id (closes the missing list id) | yes | – | Bucket(256) | 4 MiB |
| chatGroupListEntry | Hashed(group id) | yes | – | Fixed(4032 − header) | as today |
| chatContactListEntry | Hashed(account ref) | yes | – | Fixed(2048 − header) | as today |
| photosLibrary | Raw(32) incarnation | yes | yes | none | 4 MiB |
| chatAttachmentLedger | Hashed(incarnation ‖ entity) | yes | yes | none | 16 KiB |
| accountHead | none | yes (the sequence) | yes | none | 16 KiB |
| accountLocalAnchor | Raw(32) incarnation | – | – | none | 16 KiB |
| revisionSeen | Hashed(scope ‖ id) | – | – | Exact(8) | 8 |
| mailSearchStoreKey | none | – | – | Exact(32) | 32 |
| joinedMeeting | Raw(16) the row's id | – | – | Fixed(1024) | 1 KiB |
| chatProfileKeyWrap | Raw(32) profile version | yes | – | Exact(32) | 32 |

The server validates every stored one with one `validate_for(purpose,
binding, object)` and reads the revision and `previous` from the header for
its compare-and-swap. It never parses a second field: the ledger's entity
check becomes "the URL's entity hashes to the header's object", and the
profile's "matches the request" becomes the object and revision.

## Key commitment (added with slice 2, from the crypto review)

XChaCha20-Poly1305 does not commit to its key: a party that can name several
candidate keys (a server holding the OPRF key and the OPAQUE envelope can
derive candidate password KEKs) could craft one record that opens under many
of them, a partitioning oracle. `KUTPAR1` is frozen at the wipe, so the
commitment goes in now rather than as a later suite: the record's HKDF gives
a second output, `info kutup/account-record/commit/v1 ‖ header before the
commitment`, a 32-byte key commitment kept in the header after the revision
(so inside the AAD). A reader derives it and compares it in constant time
before the AEAD; a record whose commitment does not match its key is refused
there.

## Slice 2 as built

- `ContactCard` (8): the object is the SHA-256 of the contact's UID, not an
  HMAC. Contacts follow Proton's model, where the server reads the UID from
  the signed summary, so a keyed hash would hide nothing, while a plain hash
  lets the server check the card is the summary's contact (`validate_card`).
- `MailName` (9): the object is the kind byte and the 16-byte id; the ids are
  chosen by the client, so the server checks a new name against the place it
  names (`new_mail_name`).
- `IdentityPins` (10): no object. The list is one per account (its table's
  key is the user), so the account binding pins it; the "missing list id"
  above was not a gap.
- The cards', names' and pins' own keys (`derive_contacts_key`,
  `derive_names_key`, `identity_pins::derive_key`) and their magics and labels
  are gone: each seals under the master key, with the generation from the
  caller (`MASTER_KEY_GENERATION` on the web).
- Servers refuse a record's base64 longer than its purpose allows
  (`decode_record_b64`) before decoding it.
- Slice 2 needs no keyed-hash object policy; it comes with the Chat lists
  (slice 3), whose group ids and accounts the server must not see.

## Slice 3a as built

- `ChatGroupListEntry` (11) and `ChatContactListEntry` (12): the object is
  `account_record::hashed_object(master key, purpose, id)` (the group id; the
  contact's account ref), `HMAC(K_id, purpose ‖ id)` with `K_id` from the
  master key under `kutup/account-record/object-id/v1`. On the wire it is a
  32-byte object like any other (`ObjectPolicy::Required(32)`): only the
  client knows how it is made, so no separate policy was needed.
- The plaintext is padded to one length per purpose (`Fixed`), with the
  limits the lists had (3972 and 1988 bytes). With a canonical binding, a
  32-byte object and a revision, every entry is exactly one length
  (`account_record::exact_record_len`: 4144 and 2160 bytes), and the tables
  keep requiring it (migration `20261027180000`), so the server can't tell
  entries apart by their length. `KUTPGL1`, `KUTPCC1`, their id
  and seal keys and their eight labels are gone.
- The server validates each write whole: this account's entry, filed under
  the URL's entry id (`validate`), where before it read only the revision.
- Joined meetings and the profile key wrap (slice 3b) wait for the master to
  wipe-2 sync that brings #385 and #386, which moved those formats into
  kutup-crypto.

## Decisions (approved 2026-11-04)

(a) **The account head's chain moves into the header** (the server then
    refuses a head whose `previous` isn't the stored digest, as for Photos).
    Today only clients check it. Recommended: yes.
(b) **The three device-only formats (8b, 9, 10) become purposes too.** They
    never reach a server, but gain the binding, the suite and the MK
    generation for the cost of a purpose line. Recommended: yes (the plan's
    "one construction"); the alternative is to leave them as they are.
(c) **The profile key's own copy leaves `KUTPPE1`** for `chatProfileKeyWrap`.
    `KUTPPE1` stays the peer-visible profile format (name, avatar, about);
    only the owner-only wrap moves. Recommended: yes.
(d) **Joined meetings get an id** (`Raw(16)`, the client's random UUID sent
    with the row, which the server stores instead of assigning one), so an
    entry can't be swapped for another. Recommended: yes.
(e) **The contact card's signed summary stays** as it is (it is the server's
    own check, outside the envelope).

## Hashed object ids and master-key rotation

A hashed object is `HMAC(K_id, purpose ‖ id)`, where `K_id = KDF(MK, salt
kutup/account-record/v1, info kutup/account-record/object-id/v1)` (both
labels in `labels.rs`). The id is stable for as long as the master key is,
which is what the server's lookups need: a contact's card, a group's list
entry and a guard's record keep one row each.

A master-key rotation (not built; [w6-key-hierarchy.md](w6-key-hierarchy.md),
"Rotation checklist") changes `K_id`, so every hashed id changes with it. A
rotation must therefore re-seal each hashed-object record under the new
generation **and** move it to its new id (delete the old row), purpose by
purpose, or the server keeps two rows for one record and the client finds
neither under the old key. The checklist lists this.

## Slices (each into `wipe-2`, each with its vectors)

1. **The envelope.** `account_record.rs` replaces `account_envelope.rs`
   (`KUTPAR1`: a `u16` purpose, no reserved byte, the record's key derived
   over the header before the nonce, a maximum length per purpose), the six
   existing purposes moved, the server's callers and the WASM and TS API
   renamed (`sealAccountRecord`, `@kutup/crypto/accountRecord`), and
   `account-record-v1.json` with a refusal set per purpose (another suite,
   purpose, binding, object, generation or revision; a length its policy or
   maximum never gives; a cut, padded or swapped record). Each later slice
   adds the policy its purposes need, with its vectors: hashed objects
   (slice 2, contact cards; slice 3, the Chat lists), the chain (slice 4).
   Size M.
2. **Contacts, mail names, identity pins.** Their modules keep their
   plaintext codecs and lose their envelope code; the server's three
   revision checks call `validate_for`. Size M.
3. **Chat: the two lists, joined meetings, the profile key wrap.** chat-core,
   chat-proto and the server's chat handlers. Size M.
4. **The chains: Photos library, attachment ledger, account head and local
   anchor.** The server's three chain checks read the one header. Size M.
5. **Device-only: the revision guard and the mail-search wrap.** Size S.

Each slice deletes its old format, magic and vectors. No data is migrated:
wipe 2 recreates every account.

## Tests

- Rust: `account-record-v1.json` (every purpose sealed and opened, every
  refusal) in Rust and WASM; each module's own tests on the new envelope.
- The server: each handler's tests for a record from another purpose,
  binding or object, a stale revision and a broken chain.
- Browser: the suites covering each slice (contacts, mail, account, the
  clean-browser Chat suite, Photos' specs), on a lane stack built from the
  slice.
