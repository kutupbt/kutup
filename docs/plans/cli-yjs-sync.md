# CLI sync of notes, code files and place lists as Yjs

**Status:** approved design (October 2026), being built before the wipe. Until it lands, `kutup sync` leaves these files alone when they would be pulled or updated (`FileAction::SkipYjs`), records nothing for them, and says so once per file; a new one still goes up as a file.

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



**#190:** push_replacement is removed. Until this lands, `kutup sync` skips
local edits to Yjs-backed files with a clear message ("edit notes in the
browser; CLI support for them is coming"), rather than corrupting or forking
them. This lands before the wipe.
