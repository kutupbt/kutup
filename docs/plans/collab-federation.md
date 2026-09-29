# Live editing across servers

**Status:** notes and place lists implemented 2026-09-26 (migration 065,
`crates/kutup-server/src/collab_federation.rs`); verified end to end on two
servers: text and places appear on the other server within about 0.2 s, a
remote editor's version is saved with its author, and a viewer's editor
is read-only. Agreed 2026-09-26 (product owner: "each user only needs to
connect to their corresponding server; after that servers communicate",
Matrix-style push, not polling). Branch `feat/frontend-rewrite`.

## Why

Folders and files can be shared across servers (docs/plans/drive-file-sharing.md,
slice 2), but live editing (notes, place lists, office documents,
whiteboards) runs through a relay that exists on one server only: the
browser's WebSocket to `/api/files/:id/collab/ws` on the server that holds
the file. Someone on another server can view and download, not edit.

## Rules kept

- **A browser talks only to its own server.** The file's server never learns
  a remote editor's address, and the browser never holds the share's
  capability.
- **Servers only forward sealed frames.** Edits stay end-to-end encrypted,
  as they are within one server.
- **Everything between servers uses the existing signed federation
  transport:** RFC 9421/9530 signatures, replay protection and admin
  admission. Nothing new is trusted.

## Design

Call the file's server **home** and the remote editor's server **bridge**.

### Joining

The editor's browser opens its usual WebSocket, to the bridge, on a route
for the remote file:

- `/api/drive/federation/shares/:shareId/files/:fileId/collab/ws` for a file
  in a shared folder;
- `/api/drive/federation/file-shares/:id/collab/ws` for a file shared by
  itself.

The bridge authenticates the browser's session and device as usual and
keeps a local room for the remote file. When the room's first peer joins,
the bridge **subscribes** at home (`POST /api/fed/drive/collab/subscribe`,
carrying the share capability and a bridge-chosen subscription id). The
subscription is renewed while anyone is in the room, ended when the last
one leaves, and expires on its own if the bridge disappears.

### Edits from the remote editor

The bridge checks each frame as the relay does (the device's signature, the
sender id) and passes it at once to its other local peers. It batches
frames for about 50 ms and pushes them home in one signed request
(`POST /api/fed/drive/collab/frames`). Home checks the share allows
editing and that the frame is bound to the file's current key and document
key, as for a local frame. It keeps durable frames in the file's log (the
sender is recorded as that server's device), sends them to its own room,
and returns their log positions, which the bridge announces to its room as
`stored`.

### Edits from everyone else

Home pushes every new frame to each subscribed bridge
(`POST /api/fed/drive/collab/push`, signed by home, naming the
subscription). A per-subscription sender reads the log from the last
position it delivered, so pushes are ordered and nothing is skipped if one
fails (it retries with backoff; after repeated failures the subscription is
dropped). It adds the relayed-only frames (cursors, whiteboard strokes),
batches for about 50 ms, and never echoes a bridge its own frames.

### Catching up

A joining browser resumes from the last position it has, as locally. The
bridge fetches that range (`POST /api/fed/drive/collab/log`) and replays it.
If a saved version trimmed the log past it, the browser merges that version
first, as locally.

### Saving, the seed and versions

The editor's session reads and saves versions through its own server, which
relays them home, with the same checks as local saves. The relayed calls:

- `…/collab/versions` (list);
- `…/collab/versions/:id` (download);
- `…/collab/versions` (create, multipart);
- `…/collab/claim-seed`.

What a remote editor saves counts against the file owner's storage, as
uploads into shared folders already do across servers.

### Pictures in notes

A note keeps its pasted pictures as per-file assets on its home server.
A remote editor's browser stores and reads them through its own server, on
the same base (`…/assets/:assetId`, `GET` and multipart `PUT`); the bridge
relays them home over signed federation:

- `POST /api/fed/drive/collab/assets/create` — the sealed envelope (base64);
  needs the share's edit right, is validated as a local upload (the
  envelope must be bound to this file, its current key generation and the
  asset id), and counts against the owner's storage;
- `GET /api/fed/drive/collab/files/:fileId/assets/:assetId` — the envelope,
  signed; any live share of the file may read it. The key generation it was
  sealed at is not sent: the browser tries the file's keys, newest first.

### Permissions

- **Folder shares:** editing needs `can_upload`.
- **Files shared by themselves:** editing needs the new `can_edit`, which
  the owner chooses when sharing across servers too.
- **Rechecks:** home checks again on every push. A removed or narrowed share
  gets `403`/`404`, and the bridge closes its room.

## Implementation notes

- Home keeps a remote frame's sender as `(remote_domain, remote_device)` in
  `file_update_log`, with its own unique index for replay protection, and a
  remote editor's version as `file_versions.remote_author` (`user@server`).
- Subscriptions live in memory on both sides (a restart drops them; the
  bridge's renewal fails and it subscribes again). A push naming an unknown
  subscription is `404`, which ends the bridge's room.
- The browser picks its base path from where the file is:
  `/files/:id` locally, the folder or file share route otherwise
  (`collabBase` in `@kutup/drive-core/model`). The collab session, versions
  and seed all take that base.
- Reverse proxies must pass the WebSocket upgrade on the two bridge routes
  too (`nginx/nginx.conf`).

## Scope of this step

- Notes and place lists: live editing, saving and restoring; pictures pasted
  into notes.
- Office documents and whiteboards use the same relay and saves. They
  follow once their editors use the routed endpoints.

## Later

A long-lived server-to-server stream instead of per-batch requests, if
latency ever needs it. Only the transport changes.
