# CLI sync of notes, code files and place lists as Yjs

**Status:** built (October 2026), before the wipe; see *As built* at the end. `scripts/verify-yjs-sync.sh` checks it live against a server.

## The problem (wider than #190's push_replacement)

Notes and code files (`TEXT_EXT`) and place lists (`.kutupmap`) hold
collaboration state, not file bytes. Their content is the newest `yjs` version
(a Yjs V2 state update, sealed as a Drive file blob) plus the collaboration log
after its `seqAtSnapshot` (collab frames, `KIND.YJS_UPDATE`, V1 updates sealed
under the file key and doc key). A file nobody has opened yet is its original
upload, which the first editor turns into a deterministic seed
(`deterministicSeed(fileId, …)`) after winning `claim-seed`.

- **Pull is wrong today.** `download_current_stream` returns the newest
  *whole-file* version, else the upload. For a note edited in the browser the
  CLI writes the stale upload to disk, and every later browser edit is
  invisible to sync.
- **Push (#190's push_replacement)** uploads a new file and swaps it in:
  - it changes the file id, so shares, links and versions are lost;
  - it can drop collaborators' unsnapshotted edits;
  - a half-failed swap leaves two files.

## Design: the CLI edits these files as a Yjs peer, like a browser tab

1. **Yjs in Rust:** the CLI depends on `yrs`, the Yjs project's own Rust port,
   which reads and writes the same V1/V2 updates. Text docs use
   `OffsetKind::Utf16`, as JavaScript does, so indexes agree. The text lives in
   `getText('content')`; lists use the structure the Maps app uses
   (`stateToListJson`), mirrored in Rust.

2. **Reading the log without a browser:** add two endpoints beside the
   collaboration socket (same access rules as joining it):
   - `GET /api/files/:id/collab/frames?after=<seq>&limit=` returns sealed frames
     in order, plus the head and the current doc key id, paged;
   - `POST /api/files/:id/collab/frames` appends one sealed `YJS_UPDATE` frame
     from a registered collab device. The server validates its binding exactly
     as the socket path does (`persist_frame`), stores it, and broadcasts it to
     live tabs, so they merge the CLI's edit like any peer's.

   The CLI registers a collab device the way the web's `ensureRegistered` does
   (its own device key in the CLI keychain). A request/response API fits a CLI
   run better than holding a socket open; both paths share `persist_frame` and
   the frame checks.

3. **Pull:** load the newest `yjs` version (or nothing), apply every frame
   after its position, and write `content` (text) or the list's JSON export to
   disk. Record the head seq and the doc's state vector as the sync base. A file
   never opened (no yjs version, empty log) is its original upload, as the
   editor shows it.

4. **Push** of a local edit:
   - rebuild the doc from the newest version and the frames;
   - diff the local text against `content`: a character diff over UTF-16 code
     units, which maps the edit to minimal Yjs insert/delete operations, so
     concurrent remote edits elsewhere in the text merge;
   - apply it to the yrs doc and send the resulting update as one frame.

   For a list, diff entries by their ids (added, removed, changed fields) and
   apply them as map/array operations.

   **Conflicts:**
   - concurrent edits merge by Yjs's own rules (as two tabs do);
   - for a text file, a local edit made against an older remote and an edit to
     the same span merge character-wise, as in the editor;
   - no conflict copy for Yjs files.

5. **A file never opened:** the CLI claims the seed (`claim-seed`) and applies
   the same deterministic seed the editor would. That seed becomes Rust-owned
   (kutup-crypto or a shared crate), with a vector: the web's seed bytes must
   equal Rust's for the same file id and text. Then it applies its edit. If it
   loses the claim, it reads the winner's frames first.

6. **Snapshots:** after pushing, the CLI may save a `yjs` version (the full
   state at the new head), as the web's autosave does, so the log does not grow
   without bound from CLI-only use. The server trims the log as for any yjs
   version.

## Scope

- **Server:** the two frame endpoints, sharing the socket's access checks,
  `persist_frame`, broadcast and rate limits; live tests.
- **Rust:**
  - the seed derivation and vector;
  - a shared text-diff → Yjs-operations helper (in kutup-cli; or a crate the
    future native apps reuse);
  - the list mapping.
- **CLI:**
  - collab device registration;
  - materialise for pull;
  - frame push for edits;
  - the claim-seed path;
  - remove push_replacement;
  - tests against an in-memory server, and a live test with a browser tab
    merging a CLI edit.
- **Web:** use the Rust seed through WASM, so the bytes are owned in one place.



## As built

- **Planning.** A note or list on both sides is synced every run
  (`FileAction::SyncYjs`): only the log tells whether Drive's side changed.
  The check is one `GET …/collab/frames` from the recorded position. A file
  only on Drive is pulled through the log. A new local file goes up as a file
  (a document nobody has opened is its upload).
- **The base.** After each sync the CLI records the document's Yjs state and
  log position. The record is encrypted in the CLI's store, as the session
  is, since it holds the document. A local edit is diffed against that state,
  so edits made elsewhere since merge instead of being undone. After an
  upload, the base is the seed of what went up.
- **Never synced, and different on both sides.** Drive's copy is kept as a
  conflict copy, and the local file goes up as an edit over it, as for other
  files. A list counts as different only when its places differ, not its
  JSON layout.
- **Never opened.** The seed is made from the file's current content (its
  newest whole-file version, else its upload), as the editors make it.
  `kutup-collab`'s `seed_text_upload` and `seed_list_upload` read the bytes
  as the web does, and shared vectors starting from file bytes pin that
  (a byte-order mark, CRLF, invalid UTF-8, lists with missing ids and odd
  fields).
  - It is applied locally, and sent only in front of the CLI's first edit, so
    a pull writes nothing to the server.
  - As tabs do, the CLI sends it only when its `claim-seed` won. Otherwise the
    edit waits for the next run.
- **Crash safety.** No run ever makes the same edit twice as new operations:
  - **Before sending,** a local edit is recorded: the base becomes the state
    the file held, and the update bytes are kept as pending. A later run sends
    those exact bytes again until they are acknowledged, and Yjs drops a
    repeat by its client and clock.
  - **Before writing** a merged document, the base records the write it is
    about to make (hashes before and after, the merged state). The next run
    settles it from what the file holds.
  - **The stat recorded** is taken where the file was compared or written. A
    save after that point is a change for the next run, never overwritten.
  - **Writes** go through a temporary file of their own, synced to disk with
    its folder.
- **Sender sequences.** A random 31-bit prefix above the device's highest
  sequence, then a counter, as the web's `randomSenderSeqPrefix`. Two runs at
  once, or a run after the log was trimmed, never reuse a sequence.
- **Saved versions.** One `yjs` version after each edit the CLI sends, as the
  editor's autosave saves after an edit; the server trims the log there.
- **Deleted here.** Before deleting the Drive file, the CLI checks that the
  document still equals the recorded base. If it was edited elsewhere since,
  the edit wins and the file comes back.
- **The device.** Registered on first use with the account's signed
  statement (docs/plans/device-registration.md), renewed after 15 days, and
  registered again when the server answers `deviceNotAuthorized`. It is kept
  encrypted in the CLI's store and forgotten at logout.
- **Checked live.**
  - `scripts/verify-yjs-sync.sh` runs two CLI machines, including runs stopped
    after a send or a write, and a file changed mid-run.
  - Browser spec 114 (`KUTUP_CLI`) runs a tab (Yjs in JavaScript) and the CLI
    (yrs) editing one note at once.
- **Limits.** One edit goes up as one frame, so an edit over 1 MiB is
  refused with a message, as the editor's own frame limit would refuse it.
  Frames that do not open under the file key are skipped, as a tab skips
  them.

**#190:** push_replacement was removed. Until this landed, `kutup sync`
skipped these files with a message (`SkipYjs`) rather than corrupting or
forking them.
