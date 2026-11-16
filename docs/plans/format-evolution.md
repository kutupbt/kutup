# Format evolution: one rule for every format

Status: **approved** 2026-11-12 (drafted by the consultant session, 2026-11-10);
**pre-wipe rows built 2026-11-16** on `wipe/format-evolution` except where the
"Built" column says otherwise. From the format-freeze
review of `origin/wipe-2`. It must land before the wipe: the readers that
exist at the wipe are the oldest readers every later writer has to live with.

## Why

After the wipe there are clients that lag: CLI binaries people keep, native
apps that update through a store, and other servers in the federation. Today
almost every sealed or signed structure is parsed with `deny_unknown_fields`
and an exact version check. A field the web adds then makes an older client
refuse the whole object: a file's metadata, a contact's manifest, a mailbox
page, a backup segment.

Strict parsing is right where bytes are hashed or signed and both sides must
agree on them. It is wrong as the only answer to "a newer writer exists".
Signal's answer is protobuf, where unknown fields are kept and unknown enum
values are skipped, plus signed capabilities that gate new behaviour. Kutup
keeps its canonical encodings and adds the same two properties by rule.

## The rule

1. **Every plaintext names its version.** A sealed JSON plaintext has `"v"`
   (an integer) as its first field. A binary structure has a version or suite
   in its header (most already do). The caller never picks a decoder by
   context: the bytes say what they are.

2. **Two kinds of change.**
   - *Additive:* a new optional field. `v` does not change.
   - *Breaking:* a field a reader must understand to act safely, or a changed
     meaning. `v` goes up.

3. **Unknown optional fields are ignored and preserved.** A reader keeps the
   fields it doesn't know and writes them back when it rewrites the object, so
   an older client never erases a newer client's data. In Rust this is a
   flattened `extra` map in canonical (sorted) order, as the outer
   `ChatContent` already has. Limits still apply to the whole plaintext.

4. **Must-understand is explicit.** A plaintext may carry `"crit": [names]`.
   A reader that finds a name it doesn't know there refuses the object as
   *newer than me*. A higher `v` than the reader knows is refused the same
   way. Neither is *corrupt*.

5. **Three outcomes, never two.** Every decoder returns one of: ok, *newer
   than me* (show "update Kutup to open this", keep the bytes, never delete
   or overwrite), or *corrupt* (today's failure). The history-loss flow, the
   quarantine paths and "repair" actions run only on *corrupt*.

6. **Open enums, by a table.** Each enum is marked in code as one of:
   - *skip*: an unknown code is skipped, alone (a device kind, an envelope
     type, a content kind, a capability, a thumbnail format, a record type);
   - *refuse*: an unknown code refuses the object as *newer than me* (a
     suite, a purpose that selects a key, a group action that changes
     membership or rights).
   A unit test lists every enum and its class, as `labels.rs` does for labels.

7. **Signed and hashed structures stay canonical.** They are still encoded
   exactly once (sorted keys, no optional spellings), and what is signed is
   the bytes as received, unknown fields included. A verifier checks the
   signature over the received bytes and then applies rules 3 to 6. It never
   re-encodes before verifying.

8. **Capabilities gate new behaviour.** The account manifest carries, per
   device, a signed list of capability codes (u16, unknown ones skipped). A
   sender uses a new format or action toward an account only when every
   device that must read it lists the capability. Servers advertise theirs in
   the federation document, as today.

9. **Servers validate structure, not meaning.** A server checks what it must
   (lengths, headers, signatures, its own fields). It does not refuse a
   sealed object for a version or field it doesn't know, or the oldest server
   in a federation decides what clients may write.

10. **Order is defined in bytes.** Where two records tie (the Chat backup
    reducer), the winner is the smaller under a bytewise comparison of a
    stated encoding, never a language's string comparison.

## What changes, by format

Owners as the main session assigned them: W1, W5 and W6 with the second
session; Drive formats and blocks with the main session. "Assign" marks the
rest. Paths are under `crates/`; line numbers are `origin/wipe-2`.

| Format | Where | Change | Owner | Built |
|---|---|---|---|---|
| Account record envelope | `kutup-crypto/src/account_record.rs` | None to the envelope. Purposes are *refuse*. Each JSON plaintext inside follows rules 1–5. | second (W1) | **Built** (envelope): unknown purposes and suites are *newer than me*, code point 0 corrupt. The plaintexts inside follow per format: Photos library, contact cards' summaries and the others listed below; the remaining account-record plaintexts follow as each format is next touched. |
| Account head, local anchor | `kutup-crypto/src/account_head.rs` | `v`; an unknown scope is kept and still counted in the digest, not refused. | second (W1) | **Not here:** the MK rotation slice owns `AccountHeadV1` and its generations map. |
| Account manifest | `kutup-chat-proto/src/account_identity.rs:388,630` | Per-device signed capabilities; a manifest-level extension list; `DeviceKind` (`:178`) becomes *skip* for devices without Chat keys. Version check becomes rule 4. | second (W5) | **Built** (`wipe/manifest-capabilities`): per device a signed list of capability codes (`u16`, ascending, unknown kept and ignored; registry `kutup_chat_proto::Capability`: 1 `GroupChangesV1`, 2 `DriveBlocksV2`); a signed manifest-level `extensions` list (code and bytes, no code defined yet); `DeviceKind` is *skip* for an entry without Chat keys (kept by name, signed as received) and *newer than me* with them; `manifestVersion`/`minVersion` read before the fields (rule 4). Signed beside `successions` in the id-only signing bytes; empty lists sign a zero count. Devices list their build's capabilities and list themselves again after an update (web editor, CLI, Chat core). Vector: `account-manifest-v3.json` (Rust and WASM). |
| Provisioning message | `kutup-chat-proto/src/account_identity.rs:1088` | Unknown fields tolerated, so a newer device can link an older one. | second (W5) | **Built:** unknown fields ignored (`ChatProvisionV1`). |
| Drive file metadata | `kutup-crypto/src/file_metadata.rs:56,88,290` | One struct with `v` (2 for the block format); `extra` kept; `media` likewise. One `decode`, no `decode_v2`. | main | **Built:** `FileMetadata` with `v` (2, the block format; 1, a whole-file blob, refused since the block-only release), `min`, `extra` (and in `media`); `takenFrom` is *skip*; one `decode`. Web and CLI rewrites keep unknown fields. |
| Revision content | `kutup-crypto/src/revision_content.rs` (wt-blocks) | `v`, `extra`. | main | **Not here:** `revision_content.rs` is on the block-format branches (`wipe/drive-blocks`), not on this base. |
| Photos library | `kutup-crypto/src/photos_library.rs` | `v`, `extra`. | main | **Built:** `v`, `min`, `extra`. |
| Drive envelope | `kutup-crypto/src/drive_envelope.rs` | Purposes are *refuse*. No layout change here (the master-key generation is in the identity note). | main | **Built:** purposes *refuse* (newer than me). |
| Blocks and manifest | `kutup-crypto/src/blocks.rs` | Signer kind is *refuse*. Suite is *refuse*. | main | **Built:** signer kind and header suite *refuse* (newer than me). |
| Thumbnail container | `kutup-crypto/src/thumbnail.rs` | Image format is *skip* (show the generic icon). | main | **Built:** an unknown image format is newer than me (generic icon). |
| Mailbox page | `kutup-chat-proto/src/lib.rs:191,498` | `EnvelopeType` and `DirectChatSuiteId` are *skip* per envelope: the envelope is kept and acknowledged as unreadable, the page continues. | assign | **Built:** an envelope of an unknown type or suite is set apart (`MailboxPage::unsupported`), paged past and left on the server unacknowledged until the device updates; the page continues. |
| Chat content bodies | `kutup-chat-proto/src/content.rs:1284-1304` | Drop `deny_unknown_fields` on end-to-end bodies; any emoji as a reaction. The outer `ChatContent` is already right. | assign | **Built:** no `deny_unknown_fields` on bodies; any emoji is a reaction (web shows any). |
| Group state and changes | `kutup-chat-proto/src/group/mod.rs:206,334` | Stay strict and canonical. A new action is *refuse* and gated by a capability. Raise the 256 ceiling (`:66`) to the protocol's real limit; the working limit is a site setting. | assign | **Built (part):** ceiling 1000 (`MAX_GROUP_MEMBERS`, Signal's), working limit the `chat_group_max_members` site setting (1 to 256 until measured). Unknown actions still refuse as before. Every action names its capability (`GroupActionV1::capability`, all `GroupChangesV1` today, an exhaustive match) and `group::missing_capabilities` checks a change against the members' manifests. **After the wipe:** the Chat core calls it before sending a change once the first action with a capability of its own exists (roadmap, "Chat groups: gate new actions by capability"). |
| Chat backup records | `kutup-chat-proto/src/backup.rs:233,717` | A record `type` (*skip*); a newer version is *newer than me*, not a failed segment; the tie-break defined in bytes (rule 10); then the reducer and content schema move from `frontend/packages/chat-core/src/backup.ts` to Rust with vectors. | assign | **Built:** every record has a `type` (*skip*: a type a client doesn't know is kept by its frame, `recordId`, `mutationSequence`, `tombstone`, carried through reduction and compaction, never shown); a newer version is *newer than me* (`newer format: ` errors); the web tie-break compares UTF-8 bytes. **After the wipe:** the reducer and content schema move into Rust with vectors (roadmap, "Chat backup: the reducer and content schema in Rust"). |
| Chat backup base | `kutup-crypto/src/chat_backup.rs:28` | Chunked base, no single 128 MiB object. | assign | **Ready for after the wipe:** the object header already names its suite and purpose, authenticated, and a reader now checks both before the header's length, so a chunked base comes as the next version that today's readers refuse as *newer than me* (roadmap, "Chat backup: a chunked base as the next version"). |
| Contact summary and card | `kutup-crypto/src/contact_card.rs:79-91` | `v` in the bytes; pinned key with a key version and length-prefixed fingerprint. | assign | **Built:** `v`, `min`, `extra` in the signed summary, encoded with sorted keys (rule 7); pinned keys carry `keyVersion` (4: 40 hex digits, 6: 64; others kept). |
| Mail key list | `kutup-crypto/src/mail_key.rs:53,1450,1573` | Key-version byte and length-prefixed fingerprint per entry; unknown flags kept (*skip*); the 16-key cap leaves the parser. Loosen the 40-hex CHECKs. | assign | **Built:** per entry a key-version byte and a length-prefixed fingerprint; unknown versions and flags kept; the parser reads up to 256 keys and the working limit is the `mail_keys_per_address` site setting (16); fingerprint CHECKs take 40 or 64 hex digits (migration `20261111160000`). |
| Calendar metadata and events | `kutup-crypto/src/calendar.rs`, `calendar_event.rs` | `v` is there for metadata; add `extra` handling to both. | assign | **Built:** metadata `v` (renamed from `version`), `min`, `extra`, kept on a rename; every event part keeps properties it doesn't know. |
| Organization documents | `kutup-crypto/src/organization.rs` | None (magic and suite); roles stay outside the crypto. | — | Nothing to build. |
| Admin log chain | `kutup-server/src/audit_log.rs` | A `chain_version` column; every writer through `append`. | second (L2) | **Not here:** L2 (#405) owns the admin log chain; it isn't on this base. |

## Tests

- Each format's vector file gains three cases: an unknown optional field
  (opens, and a rewrite keeps it), an unknown `crit` name and a higher `v`
  (both *newer than me*), and garbage (*corrupt*).
- One browser test writes an object with an extra field and has the CLI
  rename the file: the field survives.
- The enum table test (rule 6) fails when an enum is added without a class.

## Not in this note

Suite changes and migrations between suites stay with
`docs/crypto-agility.md`. This note is about adding to a format without a new
suite.

## Open questions

1. `crit` as a list of names, or a single "minimum reader" integer per
   format? The list is finer; the integer is simpler. The recommendation is
   the integer (`"min": n`) unless a case for per-field marking appears.
2. Should servers keep rejecting unknown *purposes* of account records? Yes:
   a purpose selects a policy the server enforces. That is rule 6 *refuse*,
   and a new purpose ships server first.

## Decisions (2026-11-12)

- One "minimum reader" integer per format, not a `crit` list.
- Built before the wipe, as listed above; the owners in the table build their rows.

## As built (2026-11-16)

- **The minimum reader.** `kutup_crypto::format::check_version`: an object
  carries `"v"` and, only when lower, `"min"`; absent, the minimum is `v`.
  A reader whose version is below the minimum refuses it as
  `CryptoError::NewerThanMe`, whose text starts `newer format: `
  (`NEWER_FORMAT_PREFIX`; on the web `isNewerFormatError`). `min` equal to or
  above `v`, or 0, is corrupt. `check_json_version` reads `v` and `min`
  before the format's own struct, so a newer object whose fields no longer
  fit is still *newer*, not corrupt.
- **Unknown fields.** `format::Extra` (a sorted map) flattened into each
  struct, at most 64 names; written back after the known fields.
- **Signed JSON** (the contact summary) is encoded with every object's keys
  sorted (`format::to_sorted_json`), so a reader re-encodes exactly the
  bytes it verified whatever fields it knows.
- **Open enums.** `format::OPEN_ENUMS` classes every enum a format carries;
  `every_open_enum_has_a_class` fails when a `TryFrom<u8|u16>` enum in
  `kutup-crypto` or `kutup-chat-proto` has no row. Every suite and purpose
  registry in `kutup-crypto` answers an unknown code with *newer than me*
  and code point 0 with *corrupt*.
- **Tests.** The file-metadata vectors gain `newer` cases and an
  unknown-field round trip (Rust and WASM); each built format has unit tests
  for the three outcomes; the CLI test `rename_keeps_fields_a_newer_client_added`
  stands in for the browser test (browser suites were not run here).
