# Research: Adding WebDAV Support to kutup (forward-looking, not yet planned)

**Captured:** 2026-05-04
**Status:** Exploratory note — no spec yet, no committed scope. Captured because the user asked to keep the option in mind for a future iteration.
**Scope:** What it would take to let users mount their kutup drive as a native filesystem on macOS / Windows / Linux while preserving end-to-end encryption.

---

## 1. What users would get

WebDAV (RFC 4918) lets the operating system mount a remote URL as a drive. Once mounted, users see kutup's collections and files in:

- **macOS**: Finder via `cmd-K` → `https://kutup.example.com/webdav` (or via `mount_webdav`).
- **Windows**: File Explorer via "Map network drive."
- **Linux**: `gvfs`, `KIO` (Dolphin), `davfs2`, `rclone mount`.
- **Mobile**: native file managers on Android (Solid Explorer, X-plore) and iOS (Files app via "Connect to Server" — supports WebDAV since iOS 13).

Operations supported:
- `PROPFIND` — list directory
- `GET` — read file
- `PUT` — write file
- `MKCOL` — create directory
- `DELETE` — remove file/directory
- `MOVE`, `COPY` — rename / duplicate
- `LOCK`, `UNLOCK` — advisory file locking (rarely used)

This is the "I want to drag-and-drop files between Finder and kutup" feature. It does **not** overlap with the collaborative-editing feature (which is in-browser only); the two are complementary.

---

## 2. The fundamental tension with E2EE

WebDAV expects the server to be authoritative over file contents. The client says `GET /collection-a/notes.md` and expects plaintext bytes back. **kutup's server only has ciphertext** and cannot satisfy that request directly.

Two architectural choices:

### Option A — Server-side WebDAV gateway (rejected)

Backend exposes WebDAV directly; on `GET`, the backend would need to decrypt. **This requires the server to hold or receive the user's master key**, which breaks the zero-knowledge model. No.

This is what Nextcloud's regular WebDAV is — and exactly why Nextcloud's "E2EE" is a separate, opt-in, per-folder feature that *disables* WebDAV/preview/search for those folders. We don't want that compromise.

### Option B — Client-side WebDAV proxy (the right path)

A small daemon runs on the user's own machine, holds the master key locally, and:
- Speaks **WebDAV to the OS** on `localhost:NNNN`.
- Speaks the **regular kutup REST API + the existing E2EE primitives** to the kutup server.
- Decrypts on `GET`, encrypts on `PUT`, applies the same per-collection / per-file key model that the web UI and CLI use.

The kutup server is unchanged — it sees only the regular authenticated REST traffic from the CLI/daemon. The encryption boundary stays on the user's device.

**This is the only viable path under E2EE.** It's also what the precedent set by other E2EE products uses.

---

## 3. Prior art

| Product | Approach | Notes |
|---|---|---|
| **Cryptomator** | Local virtual filesystem (WinFsp / macFUSE / FUSE) plus a built-in WebDAV server at `localhost:42427` as universal fallback. App runs locally and holds the vault key. | The reference implementation for "WebDAV under E2EE." Cryptomator vault format is widely understood. |
| **Filen Desktop** | "Network Drive" feature — local WebDAV server bundled into the desktop app. Decryption happens on the client side. | Similar pattern; commercial product. |
| **Nextcloud** | Server-side WebDAV (plaintext on server). Their per-folder E2EE *disables* WebDAV for those folders. | Counter-example — what we want to avoid. |
| **Proton Drive** | No WebDAV. Custom protocol + native desktop sync clients only. | Shows you can ship without WebDAV, but power users miss it. |
| **ownCloud Infinite Scale** | Server-side WebDAV (no E2EE by default). | Same as Nextcloud. |
| **rclone** | Treats kutup as a remote; rclone holds the key, mounts as a virtual filesystem locally. Could work today *if* kutup ships an rclone backend, but feels like outsourcing the problem. | Worth considering as a "free win" alternative or stopgap. |

---

## 4. How this fits with kutup's existing CLI

kutup already ships a Go CLI (`cli/`) that:
- Holds the user's master key locally (OS keyring + BoltDB session encryption, per `cli/internal/session/store.go`).
- Implements upload / download / list with E2EE (`cli/internal/api/`, `cli/internal/crypto/`).
- Has a `sync` command for bidirectional folder sync.

A WebDAV mode is a natural extension — same key handling, same crypto, just a different I/O surface. New command:

```
kutup mount --webdav :8080
```

Spawns a WebDAV server on `localhost:8080`. User points Finder/Explorer/etc. at `http://localhost:8080`. The server translates WebDAV calls into the CLI's existing API+crypto stack.

Implementation:
- **Library:** Go's standard library `golang.org/x/net/webdav` (BSD-3, well-maintained, used by Caddy and many others). Provides the protocol layer; we provide a `webdav.FileSystem` implementation backed by kutup.
- **Caching:** the daemon needs an LRU cache for recently-accessed file plaintexts so editors that do many small `GET`s (`PROPFIND`+`GET` per file) don't trigger thousands of decryptions. Encryption-at-rest in the cache (encrypted with a session key in memory).
- **Locks:** WebDAV `LOCK` semantics are advisory; can be no-ops for now (warn but accept). Our collaborative-edit feature is browser-only, so WebDAV writes don't need to coordinate with it (a future v2 could offer "open in browser editor" links).
- **Authentication:** present a Basic auth dialog to Finder on first connect; CLI translates into a kutup session token.

---

## 5. Interaction with the collaborative-edit feature

WebDAV mode and live collaborative editing are **independent surfaces** for the same files:

- WebDAV does not do real-time collab. Files are read on `GET`, written wholesale on `PUT`. No CRDT, no presence.
- If user A is live-editing `notes.md` in the browser editor and user B writes the same file via WebDAV, kutup needs a conflict-resolution policy. Realistic options:
  - (i) **Refuse the WebDAV write** if the file has an active collab session — return `423 Locked`. Simplest.
  - (ii) **Snapshot + force conflict file** — accept the WebDAV write as a new version, name the prior live state as a conflict copy. More like Dropbox.
  - (iii) **Translate WebDAV writes into editor-equivalent ops** — far too much complexity for the value.

  Recommendation: (i) for v1 — return `423` with a Retry-After when an active collab session exists; the desktop user retries after the browser editor closes. Reconsider (ii) once we have real users complaining.

---

## 6. Security caveats

- **Local-only binding.** The CLI's WebDAV server must bind to `127.0.0.1` (or a Unix socket) by default. Anything else exposes the user's plaintext mount to the network.
- **Auth on localhost.** Even on `127.0.0.1`, OS-level isolation isn't perfect (other users on the same machine, browser CSRF). Require Basic auth with a per-mount random token; reject Origin headers (browsers shouldn't talk to this server).
- **Plaintext lifetime.** The cache keeps decrypted bytes in memory; clear on lock / logout / inactivity.
- **TLS.** Optional but useful — issue a per-install local cert via mkcert-style flow if/when we want HTTPS-only mounts. Probably overkill for v1.

---

## 7. What kutup would need on the server side

Almost nothing. The CLI/daemon talks to existing REST endpoints:

- `GET /api/collections/` — list collections (translates to top-level WebDAV directories).
- `GET /api/collections/:id/files` — list files in a collection (WebDAV `PROPFIND`).
- `POST /api/files/upload`, `GET /api/files/:id/download`, `DELETE /api/files/:id` — read/write/delete (WebDAV `PUT`/`GET`/`DELETE`).
- The collab-edit endpoints (`/collab/ws`) are not used by WebDAV.
- A new advisory **lock check endpoint** would be nice (so WebDAV can return `423` when a collab session is active): `GET /api/files/:id/collab/active` → `{ active: bool, count: int }`. Cheap to implement.

No schema changes required.

---

## 8. Open questions (to resolve when this gets prioritized)

1. **Rename semantics.** A WebDAV `MOVE` becomes a "rename file" — which today involves re-encrypting the filename with the collection key. Cheap. But cross-collection `MOVE`? Need to either re-wrap the file key under the destination collection's key, or refuse cross-collection moves. Refusing is simpler for v1.
2. **Trash / soft delete.** WebDAV `DELETE` is hard. Should the kutup desktop daemon route deletions through a local trash directory first? Probably yes, mirroring native trash behavior.
3. **Streaming large files.** `PUT` of a 5 GB file shouldn't be buffered in memory before encryption. Use kutup's existing chunked-streaming upload primitive.
4. **Multiple concurrent mounts** (user has both Finder + an editor mounted simultaneously). Should be fine as long as both go through the same daemon process — the in-process LRU cache deduplicates.
5. **Collab-session conflict UX.** Pick (i)/(ii)/(iii) from §5; iterate based on real-world friction.
6. **Authentication UX.** Basic-auth dialog is ugly. Could we pre-mount via OS keychain integration?
7. **Cross-platform packaging.** The CLI is already cross-platform; WebDAV mode adds nothing. But for a *desktop app* with FUSE/WinFsp instead of WebDAV (faster, more featured), each platform has its own kernel-driver dependency.
8. **rclone alternative.** Should we ship an rclone backend for kutup as a quick win for power users, before committing to a built-in WebDAV server? rclone already has FUSE mount, sync, cache, encryption — it might cover 80% of the value with 5% of the work.

---

## 9. Tentative scope when this becomes real

**v1 (CLI WebDAV mode):**
- `kutup mount --webdav <addr>` command.
- Implements PROPFIND/GET/PUT/DELETE/MKCOL/MOVE on `golang.org/x/net/webdav`.
- LRU plaintext cache, encrypted in memory with a session key.
- Returns `423 Locked` if a file has an active collab session.
- Localhost-only binding by default.
- ~1-2 weeks of work after the core collab-edit feature ships.

**v2 (rclone backend):**
- Probably easier and broader than DIY WebDAV. Implement the rclone backend interface. Users get FUSE mount, sync, encryption-aware caching, etc., for free.

**v3 (native FUSE/WinFsp desktop app):**
- True virtual filesystem, no WebDAV layer. Uses macFUSE / WinFsp / FUSE3.
- Much better performance and integration than WebDAV.
- Cross-platform packaging is the hard part.

---

## 10. Decision deferred

This note exists so the WebDAV idea isn't lost. **No design or schema work is committed.** The collab-edit feature ships first; WebDAV is reconsidered after v1 of that lands and we have real users telling us what they actually want.

If we do greenlight it later, **client-side proxy bundled into the existing CLI** is the only path that preserves E2EE. Server-side WebDAV is not on the table.
