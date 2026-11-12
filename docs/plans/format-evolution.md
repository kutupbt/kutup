# Format evolution: one rule for every format

Status: **approved** 2026-11-12 (drafted by the consultant session, 2026-11-10), from the format-freeze
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

| Format | Where | Change | Owner |
|---|---|---|---|
| Account record envelope | `kutup-crypto/src/account_record.rs` | None to the envelope. Purposes are *refuse*. Each JSON plaintext inside follows rules 1–5. | second (W1) |
| Account head, local anchor | `kutup-crypto/src/account_head.rs` | `v`; an unknown scope is kept and still counted in the digest, not refused. | second (W1) |
| Account manifest | `kutup-chat-proto/src/account_identity.rs:388,630` | Per-device signed capabilities; a manifest-level extension list; `DeviceKind` (`:178`) becomes *skip* for devices without Chat keys. Version check becomes rule 4. | second (W5) |
| Provisioning message | `kutup-chat-proto/src/account_identity.rs:1088` | Unknown fields tolerated, so a newer device can link an older one. | second (W5) |
| Drive file metadata | `kutup-crypto/src/file_metadata.rs:56,88,290` | One struct with `v` (2 for the block format); `extra` kept; `media` likewise. One `decode`, no `decode_v2`. | main |
| Revision content | `kutup-crypto/src/revision_content.rs` (wt-blocks) | `v`, `extra`. | main |
| Photos library | `kutup-crypto/src/photos_library.rs` | `v`, `extra`. | main |
| Drive envelope | `kutup-crypto/src/drive_envelope.rs` | Purposes are *refuse*. No layout change here (the master-key generation is in the identity note). | main |
| Blocks and manifest | `kutup-crypto/src/blocks.rs` | Signer kind is *refuse*. Suite is *refuse*. | main |
| Thumbnail container | `kutup-crypto/src/thumbnail.rs` | Image format is *skip* (show the generic icon). | main |
| Mailbox page | `kutup-chat-proto/src/lib.rs:191,498` | `EnvelopeType` and `DirectChatSuiteId` are *skip* per envelope: the envelope is kept and acknowledged as unreadable, the page continues. | assign |
| Chat content bodies | `kutup-chat-proto/src/content.rs:1284-1304` | Drop `deny_unknown_fields` on end-to-end bodies; any emoji as a reaction. The outer `ChatContent` is already right. | assign |
| Group state and changes | `kutup-chat-proto/src/group/mod.rs:206,334` | Stay strict and canonical. A new action is *refuse* and gated by a capability. Raise the 256 ceiling (`:66`) to the protocol's real limit; the working limit is a site setting. | assign |
| Chat backup records | `kutup-chat-proto/src/backup.rs:233,717` | A record `type` (*skip*); a newer version is *newer than me*, not a failed segment; the tie-break defined in bytes (rule 10); then the reducer and content schema move from `frontend/packages/chat-core/src/backup.ts` to Rust with vectors. | assign |
| Chat backup base | `kutup-crypto/src/chat_backup.rs:28` | Chunked base, no single 128 MiB object. | assign |
| Contact summary and card | `kutup-crypto/src/contact_card.rs:79-91` | `v` in the bytes; pinned key with a key version and length-prefixed fingerprint. | assign |
| Mail key list | `kutup-crypto/src/mail_key.rs:53,1450,1573` | Key-version byte and length-prefixed fingerprint per entry; unknown flags kept (*skip*); the 16-key cap leaves the parser. Loosen the 40-hex CHECKs. | assign |
| Calendar metadata and events | `kutup-crypto/src/calendar.rs`, `calendar_event.rs` | `v` is there for metadata; add `extra` handling to both. | assign |
| Organization documents | `kutup-crypto/src/organization.rs` | None (magic and suite); roles stay outside the crypto. | — |
| Admin log chain | `kutup-server/src/audit_log.rs` | A `chain_version` column; every writer through `append`. | second (L2) |

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
