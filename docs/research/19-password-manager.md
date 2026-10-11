# Kutup Pass: a password manager for Kutup

**Status:** research, 2026-10-11. No implementation, no spec, no committed scope. Branch `docs/password-manager-research`.

**Scope.** What a password manager inside Kutup ("Kutup Pass", at `pass.<domain>`) should look like, based on reading the code of eleven existing products: KeePassXC, KeePassDX, Keepass2Android, KeePassium, Strongbox, Password Safe, Bitwarden (clients, server, Rust SDK), Vaultwarden, Proton Pass (web, extension, desktop, Android, iOS) and Passbolt. The document covers their strong and weak parts, a field model that holds everything KeePassXC holds, and a design proposal that builds on what Kutup already has (account master key, Ed25519 account authority, identity pins, Drive's signed key epochs, HPKE named shares, encrypted IndexedDB records, one storage pool).

**Method.** Five code-reading passes over shallow clones in `kutup-references/` (commits in §8), one per product group plus one cross-cutting pass on SSH keys, passkeys, TOTP, mobile autofill, browser extensions and backup. The per-product working notes were not committed; their evidence is carried into this document. Kutup facts were checked against this repository on 2026-10-11.

**Evidence conventions.** A reference such as `KXC/core/Merger.cpp:439-492` points into a shallow clone in `kutup-references/` (the read-only reference checkouts kept beside this repository; its `README.md` lists URLs and commits) and was read in the code. **[GK]** marks general knowledge that was not checked in the clones and may be stale. Prefixes:

| Prefix | Path under `kutup-references/` |
|---|---|
| `KXC` | `keepassxc/src` |
| `KDX-APP` / `KDX-DB` | `keepassdx/app/src/main/java/com/kunzisoft/keepass` / `keepassdx/database/src/main/java/com/kunzisoft/keepass` |
| `K2A` | `keepass2android/src` |
| `KPM-Lib` / `KPM-AF` | `keepassium/KeePassiumLib/KeePassiumLib` / `keepassium/KeePassium AutoFill` |
| `SBX` | `strongbox` |
| `PWS` | `pwsafe` |
| `BSDK` | `bitwarden-sdk-internal/crates` |
| `BWC` | `bitwarden-clients` |
| `BWN` | `bitwarden-clients/apps/desktop/desktop_native` |
| `BWS` | `bitwarden-server/src` |
| `VW` | `vaultwarden` |
| `PPW` / `PPX` / `PPD` | `WebClients/packages/pass` / `WebClients/applications/pass-extension/src` / `WebClients/applications/pass-desktop` |
| `PPA` / `PPI` | `proton-pass-android` / `proton-pass-ios` |
| `PB` | `passbolt-api` |

Kutup paths (`crates/…`, `docs/…`) are relative to this repository.

## The requirements

What the product owner asked for, and where this document answers it:

- [ ] A password manager in Kutup, web first → §5, phases in §6.
- [ ] Native iOS and Android apps later, so the structure must not assume a browser → §5.6, §5.14, P5 in §6; one native app per product ([`../mobile-build.md`](../mobile-build.md)).
- [ ] Offline use: read **and** write without the server → §5.5, §5.6.
- [ ] Backup → §5.13.
- [ ] SSH keys → §5.8.
- [ ] Every field KeePassXC supports → §4 (lossless KDBX 4.1 round-trip).
- [ ] Password sharing and shared accounts between Kutup users, including users on other Kutup servers → §5.7.
- [ ] Study KeePassXC, Strongbox, Password Safe, Bitwarden, Proton Pass, plus KeePassDX, Keepass2Android, KeePassium, Vaultwarden and Passbolt, with their strong and weak parts → §2, §3.
- [ ] Research only: nothing is built on this branch.

---

## 1. Executive summary

1. **Nobody studied does all of "offline writes + real sharing + KeePassXC fields".** The KeePass family and Password Safe are offline-first but share by handing out a file and its password. Bitwarden, Proton Pass and Passbolt share properly but are online-only for edits: Bitwarden and Proton refuse writes offline (`BWC/libs/common/src/vault/services/cipher.service.ts:804-925`, `PPW/components/Layout/Panel/ItemViewPanel.tsx:208`). Passbolt's offline mode arrived in 5.16.0 (2026-09-16) and is opt-in per item, time-boxed and admin-capped (`PB/plugins/PassboltCe/OfflineMode`). Kutup Pass would be the first of this group with all three.
2. **Store items as records, not as one file.** Every file-based product re-invents sync on top of a whole-database blob, and every one of them loses or buries edits somewhere: whole-entry last-writer-wins on device clocks at second precision (KeePassXC `KXC/core/Merger.cpp:439-492`, Strongbox `SBX/model/Sync/DatabaseMerger.m:304-333`), unconditional overwrites (KeePassDX, Strongbox's Dropbox push `SBX/StrongBox/DropboxV2StorageProvider.m:263`), or no merge at all (KeePassium, `keepassium/KeePassium/database/DatabaseSaving.swift:109-135`). One encrypted record per item, server revisions, conditional writes and a durable offline outbox remove those failure modes.
3. **Seal each item as one blob under its own key.** Bitwarden's per-field encryption leaks structure and allows field swapping; Bitwarden is itself moving to whole-item sealed blobs (`BSDK/bitwarden-vault/src/cipher/README.md`). Proton already uses vault key → item key → item content with AAD tags (`PPW/lib/crypto/utils/crypto-helpers.ts:14-18`). Kutup should do the same with XChaCha20-Poly1305 and AAD that binds item, revision and schema.
4. **Kutup already has the hard sharing primitives.** Drive's signed, hash-linked key epochs (`crates/kutup-crypto/src/collection_epoch.rs`), the walk-back keyring (`collection_keyring.rs`), per-object key generations (`file_keyring.rs`), HPKE named-share envelopes to local and federated users (`named_share.rs`) and identity pins with safety numbers (`identity_pins.rs`, `safety_number.rs`) map directly onto vaults, items, and invitations. Proton Pass has the same tree but fetches recipients' keys with no verification UI and never rotates keys on removal (`PPW/lib/shares/share.requests.ts:66-70` only deletes a server row). Bitwarden has no organization-key rotation at all. Kutup can do both.
5. **Revocation needs both crypto and honesty.** Rotate the vault key on every removal or expiry (new epoch; old item keys re-wrapped lazily), and flag every item the removed person could read as "exposed to a former member, change these". Passbolt's "expire on access loss" (`PB/plugins/PassboltCe/PasswordExpiry/src/Service/Resources/PasswordExpiryExpireResourcesService.php:28-36`) is the precedent: no crypto takes back a password someone already saw.
6. **KeePassXC parity means a lossless KDBX 4.1 codec in `kutup-crypto`.** KDBX has no item types; everything is strings, attachments, custom data and conventions (`otp`, `KP2A_URL*`, `KPEX_PASSKEY_*`, `KeeAgent.settings`). Kutup should have typed items (Bitwarden/Proton style) plus an extension bag that keeps every KDBX attribute it does not model, and prove parity by round-tripping KeePassXC's own test databases (`keepassxc/tests/data/`).
7. **SSH keys: a first-class item type plus an agent in the `kutup` CLI.** Copy Bitwarden's agent design (in-memory keystore, approval per signature, `session-bind@openssh.com` host display, git-signing namespace; `BWN/ssh_agent/src/authorization.rs:31-110`) and Strongbox's "list keys while locked, unlock on use" (`SBX/macbox/ssh-agent/SSHAgentRequestHandler.swift:108-145`). Keep a KeePassXC-style "push into the system agent with constraints" mode. Export as `KeeAgent.settings` + key attachment.
8. **A web app can store passkeys and show TOTP, but cannot fill or sign for other sites.** Autofill and passkey use need a browser extension and, on phones, the native app. The web vault is the management UI and must work without them. Phase the extension and the native app after the vault, sharing and SSH work.
9. **Never run Argon2 in an iOS AutoFill extension.** Kutup's account Argon2id is fixed at 64 MiB (`crates/kutup-crypto/src/kdf.rs:24-26`), at the edge of what KeePassium and Strongbox warn about inside the ~120 MB extension limit (`KPM-Lib/util/MemoryMonitor.swift:12`). Native apps should unwrap a random device key with Secure Enclave / Keystore + biometrics and decrypt only the matched item.
10. **Licences allow reading everything and copying much, but re-implement anyway.** Kutup is AGPL-3.0-only (`Cargo.toml:21`). GPL-3 and AGPL-3 code can be combined [GK, confirm with counsel]; the Bitwarden SDK's GPL-3.0 option is usable, its "SDK License" option and everything under `bitwarden_license/` are not. The designs are worth more than the code; the shared core should be Kutup's own Rust.

**Recommended direction in one paragraph.** Build Kutup Pass as a new web app on its own origin, backed by a new `pass` area of `kutup-server` and new modules in `kutup-crypto` (WASM for web, UniFFI for native, used by the `kutup` CLI). Each item is one encrypted record under its own item key; item keys are wrapped by a vault key that is a Drive-style signed epoch chain; vault keys reach members as HPKE named-share envelopes checked against identity pins, locally and across federation. Clients keep a full encrypted replica (IndexedDB on the web) and write offline into an outbox; the server accepts revision-conditional writes and publishes a change feed; conflicts are merged per field, with losing values kept in history. The item model is a typed superset of Bitwarden, Proton Pass and KeePassXC, and KDBX 4.1 export/import is lossless. SSH keys get an agent in the CLI; the browser extension and the native Kutup Pass app come later and reuse the same core.

## Priorities (decided 2026-10-11)

The product owner set the order after reading this research:

1. **Offline is the number one need.** Kutup Pass must work offline in the client apps, and that offline behaviour must be **stable when the client apps arrive** — not added to them later.
2. **The product being built now is the website** (`pass.<domain>`). It uses the offline engine too, but the website's own offline use is best-effort (see §5.6: offline unlock is new work, and iOS Safari can evict a site's storage after about a week without use [GK]).
3. **Storage:** superseded the same day by the direction below — the vault is a **KDBX file in Kutup Drive**, with Kutup's three-way merge. The per-item record design (§5.1a, §5) is kept as the later path for per-item sharing.
4. **Sharing is not the most important problem now.** It moves to the end of the plan (§6). Nothing in the data model may block it later: the vault-key epochs, item-key generations and envelopes stay in the format from day one, so sharing is added without a migration.

What this meant for the per-item design (now the later path, §5): the offline engine — local replica, durable outbox, revision-conditional sync with a change feed, field-level three-way merge, tombstones, resync, offline unlock and the device-key wrapping — is built **first, once, in the shared Rust core**, and proven before any client UI depends on it. The website, the `kutup` CLI and the later native Kutup Pass app (and the extension) all run that same engine, so the native apps add UI and platform glue, not a second offline implementation.

## Direction (decided 2026-10-11): KDBX in Kutup Drive, with Kutup's three-way merge

After comparing Proton Pass (per-item records, offline read-only), Strongbox and KeePassXC (a KDBX file, offline editing by design), the product owner chose the KDBX model: **editing offline is the requirement**, and a KDBX file is how the apps they already use every day work, without depending on a service being reachable. Kutup's contribution is to store and sync that file safely and to merge it better than the KeePass apps do.

### What it is

- **The vault is one KDBX 4.1 file in Kutup Drive** (for example in a `Passwords` folder). It is encrypted twice: by KDBX (Argon2id + AES-256 or ChaCha20, under the vault password) and by Drive's end-to-end encryption on top. The server sees only Drive ciphertext.
- **Every client keeps a local copy and edits it offline.** Nothing about editing needs the server; sync happens when a connection is there.
- **Drive keeps every version** of the file (Drive version history exists today), so a bad save can be rolled back, and Kutup has the common starting version for merging.
- **KeePassXC keeps working on desktop** through `kutup sync`, with its autofill, passkeys and SSH agent. On phones the Kutup Pass website is the client for now; the KeePass phone apps (Strongbox, KeePassium, KeePassDX, Keepass2Android) can open the file once a Kutup native app makes Drive reachable from the phone.
- **Leaving Kutup is trivial**: the vault is a standard KeePass file.

### Clients and how each edits offline

| Client | How it reaches the file | Offline editing | Who merges |
|---|---|---|---|
| **Kutup Pass website** (`pass.<domain>`, the product built now) | Opens the KDBX from Drive and decrypts it in the browser (KDBX codec in the Rust core, WASM) | Edits the local copy; the save waits in an outbox (encrypted, in IndexedDB) until online | Kutup (three-way) |
| **Desktop: KeePassXC + `kutup sync`** | `kutup sync` (exists today, with a three-way-merge sync engine for folders) keeps a local folder in sync; KeePassXC opens the file there. Double encryption intact | KeePassXC edits the local file | Kutup: `kutup sync` learns to merge KDBX files (decrypting with the vault password) instead of producing a conflict copy |
| **Phones, now** | The Kutup Pass website in the phone's browser | As the website (best-effort offline on mobile browsers, §5.6) | Kutup (three-way) |
| **Phones, later** | Kutup's native apps ([`../mobile-build.md`](../mobile-build.md)): a native Kutup Pass and/or a Kutup Drive app exposing Drive to the system Files app, so Strongbox, KeePassium, KeePassDX and Keepass2Android can open the file with both encryption layers intact | The app edits its local copy and uploads later | Kutup's native app (three-way), or the KeePass app with its own rules followed by Kutup's re-merge (below) |

**No WebDAV, CalDAV or CardDAV for phones** (decided 2026-10-11). Proton offers none of them; serving them from Kutup's server would mean handing it readable data (for the vault file: KDBX encryption only, without Drive's layer — [`06-webdav-support.md`](06-webdav-support.md)). Phones use the website until Kutup's native apps arrive.

### KeePassXC's merge, the starting point (`KXC/core/Merger.cpp`)

Read in the code (765 lines):

- **When it runs**: automatically when the open file changes on disk and there are unsaved changes ("reload and merge", `KXC/gui/DatabaseWidget.cpp:2217`); manually via Database → Merge with a dry-run preview (`KXC/gui/MergeDialog.cpp:159, 185`); `keepassxc-cli merge`; KeeShare imports.
- **Matching**: entries and groups by UUID; a missing one is added with its history (`mergeGroup`, `Merger.cpp:186-330`).
- **Moves**: applied if the other side's "location changed" time is newer.
- **Conflicting entry**: the **newer whole entry wins** by last-modification time, compared at one-second precision; the losing entry is added to the winner's history, and both histories are unioned by modification time (`resolveEntryConflict_MergeHistories`, `mergeHistory`, `Merger.cpp:439-605`). Equal times with different contents only log "conflict resolution may lose data" (`:541-548`).
- **Groups**: the newer group's name, notes and icon replace the other's.
- **Deletions**: the two deleted-objects lists are unioned; a deletion applies unless the object was edited after it — in Synchronize mode only (`mergeDeletions`, `:607`).
- **Metadata**: partly; the authors' own TODO notes the recycle bin, templates and similar as a "possible lost update" (`:702-704`).

Its limits: there is no common base, so it cannot tell "only I changed this field" from "we both did", and it must pick a whole entry; **device clocks decide**; database settings can be lost.

### Kutup's three-way merge

The same rules, plus the one thing KeePassXC lacks: the version both edits started from, which Drive already keeps.

- **Inputs**: *base* (the Drive version the client last synced and started editing from; the client records its id), *ours* (the local edited file) and *theirs* (the current file on Drive).
- **Matching**: entries and groups by UUID, as KeePassXC.
- **Per entry, per field**: title, username, password, URL, notes, every custom string (and its protected flag), `KP2A_URL*` / `URL_n`, `otp` and the other TOTP forms, `KPEX_PASSKEY_*`, tags (as a set), attachments (by name and content hash), icon, expiry, auto-type, custom data per key.
  - changed on one side → that change applies;
  - changed on both sides to the same value → no conflict;
  - changed on both sides to different values → *ours* is written (it is the save landing last on the server), *theirs* goes into the entry's history, and the entry is marked for review (a custom-data key such as `KutupMergeReview`, which other KeePass apps keep and ignore). Passwords get a visible notice, because both may be real.
- **History**: unioned by modification time (KeePassXC's `mergeHistory`), within the database's history limits.
- **Moves**: three-way on the parent group; a move on one side applies, moves on both sides → ours.
- **Deletions**: deleted-objects lists unioned; **deleted on one side but edited on the other after the base → the edit wins**, the entry is restored and the user told.
- **Groups and database metadata**: three-way per field, including recycle bin, history limits, custom icons (union) and custom data — closing KeePassXC's "possible lost update".
- **No device clocks decide anything.** Timestamps are kept as data, not used to pick winners.
- **Fallback without a base** (a file of unknown origin): KeePassXC's rules.
- The engine lives once in the Rust core (WASM for the website, the `kutup` CLI, UniFFI for a later native app), with KeePassXC's own test databases (`keepassxc/tests/data/`) for round-trips and property tests that no field change is lost.

### Saving without overwriting

- **Kutup clients save conditionally**: "this file, based on Drive version N". If the file moved on, the client fetches it, merges, and saves again. A save never replaces a version it has not seen. (Recording which version an upload is based on is new in Drive.)
- **The server cannot merge**: it cannot decrypt the file. Merges always run on a client that holds the vault password.
- **Diverged versions** (two devices saved without seeing each other, for example once KeePass phone apps reach the file through a later native Drive app): Drive records each upload as a new version with the version it replaced; the next Kutup client that opens the vault — the website or `kutup sync` — runs the three-way merge with the common ancestor and saves the result. Until then both versions are kept; nothing is dropped.
- Whatever another app's own merge decided, Kutup's later re-merge against the common base restores field changes it may have buried in history.

### What the earlier research becomes

- **Still applies**: the field model (§4, now native: the vault *is* KDBX), the KDBX 4.1 codec, TOTP, the security monitor (on the website), the lessons from every product studied.
- **SSH keys**: decided below ("SSH agent in the `kutup` CLI").
- **The per-item record design (§5.1a–§5.15) is the later path**, for when per-item sharing between users or Kutup's own autofill becomes important. Importing a KDBX makes that move straightforward. Until then, a family or team shares a vault by keeping its KDBX file in a shared Drive folder (Drive sharing, with revocation and key rotation, already exists), with the vault password shared out of band.

### Phases for this direction

| Phase | Contents |
|---|---|
| **K0** | KDBX 4.1 codec (read every variant KeePassXC reads; write 4.1) and the three-way merge engine in the Rust core; KeePassXC test corpus; merge property tests |
| **K1** | `kutup sync` merges KDBX files instead of making conflict copies — the first offline client (desktop with KeePassXC) |
| **K2** | The Kutup Pass website: open, view, edit and create entries in a KDBX from Drive; local copy and save outbox for offline; version history and rollback; conflict review |
| **K3** | Divergence detection and re-merge of diverged versions by Kutup clients; the website tuned for phone browsers |
| **K3b** | The opt-in SSH agent in the `kutup` CLI (below); can start right after K1, since it reads the vault `kutup sync` keeps |
| **K4 (later)** | Kutup's native apps: Kutup Pass and/or the Kutup Drive app with system Files integration, so KeePass phone apps can open the vault with both encryption layers; the per-item path (§5) if sharing items between users becomes important |

### SSH agent in the `kutup` CLI (decided 2026-10-11)

The `kutup` CLI includes an SSH agent, **opt-in**: installing the CLI never starts it or changes SSH settings.

- **Keys are ordinary KeePass entries** in the `KeeAgent.settings` form KeePassXC and Strongbox already use (key as an attachment or file reference, passphrase in the entry password). The same entry works in KeePassXC's agent integration, Strongbox's macOS agent and the `kutup` agent; nothing is Kutup-only.
- **Offline**: the agent reads the vault from the local folder `kutup sync` keeps, so SSH works without a connection, like the vault itself.
- **Where it helps most**: terminals, servers and remote machines where no GUI password manager runs.
- **Starting it**: `kutup ssh-agent` in the foreground, or `kutup ssh-agent install` to set it up as a user service (systemd user unit, launchd agent, Windows service on its own named pipe beside the built-in OpenSSH agent). Installing it never rewrites `SSH_AUTH_SOCK` behind the user's back; it prints what to set. If KeePassXC's or Strongbox's agent is already serving, it says so instead of competing.
- **Approval per use** (Bitwarden's model, `BWN/ssh_agent/src/authorization.rs`): a desktop notification or terminal prompt shows the requesting process, the destination host (from `session-bind@openssh.com`), whether the request is **forwarded** (`ssh -A`, flagged prominently), and whether it is a login or a git signature (SSHSIG namespace). Choices: allow once, remember for this host until lock, deny; per key, "never ask" for those who want it.
- **Keys listed while locked** (Strongbox, `SBX/macbox/ssh-agent/SSHAgentRequestHandler.swift:108-145`): SSH sees the public keys; the first signature request asks to unlock.
- **Memory only**: private keys are decrypted from the vault into memory, never written to disk, and wiped on lock, idle timeout and sleep.
- **Push mode for people who keep their own agent**: `kutup ssh-add <entry> --lifetime 1h --confirm` adds a key to the system agent with constraints (KeePassXC's way, `KXC/sshagent/SSHAgent.cpp:270-304`).
- **Unlocking**: in a terminal the agent can ask for the vault password; for background use it is smoother when the vault password is stored under the Kutup account key (open question 1 below).
- **Crypto**: the RustCrypto `ssh-key` crate in the shared core (generation, import of OpenSSH / PKCS#8 / PKCS#1, fingerprints), the same code the website uses to show and create SSH key entries.

### Open questions for this direction

1. **Where the vault password lives.** Pure KeePass: the user types it (one more password). Convenience: Kutup stores it wrapped by the account master key, so the website and `kutup sync` unlock with the Kutup sign-in; the KeePass apps still ask for it.
2. **Key files and YubiKey challenge-response**: support them in the website and `kutup sync`, or password-only for vaults Kutup merges?
3. **One vault file per user, or several** (personal, shared family vault in a shared folder)?

---

## 2. Products studied

### 2.1 KeePass family: KeePassXC and the KDBX format

**Architecture.** KeePassXC (C++/Qt, commit `9e0f57a`) is a desktop app around one encrypted file. The file *is* the database; there is no server. Sync is whatever moves the file (Syncthing, Dropbox, scp) plus a merge engine.

**Storage and crypto (KDBX 4.x).**
- Layout: signatures, version, outer header TLVs, SHA-256 of the header, header HMAC, then an HMAC block stream of ciphertext over optionally gzipped inner header + XML (`KXC/format/KeePass2.h:29-40`, `KXC/format/Kdbx4Writer.cpp:30-192`). A fresh master seed, IV and inner stream key on every save (`Kdbx4Writer.cpp:46-48`).
- KDFs: AES-KDF (default 1,000,000 rounds), Argon2d, Argon2id; KeePassXC defaults to 10 iterations, 64 MiB, parallelism min(cores, 4) (`KXC/crypto/kdf/Argon2Kdf.h:23-26`), with a 1 s benchmark target (`Kdf.h:54-62`).
- Ciphers: AES-256-CBC (default), ChaCha20, Twofish-CBC (`KXC/crypto/SymmetricCipher.cpp:158-172`). No AEAD; integrity comes from the HMAC block stream with block index binding (1 MiB blocks, `KXC/streams/HmacBlockStream.cpp:27, 124-171`). The header HMAC doubles as the wrong-password detector (`Kdbx4Reader.cpp:76-81`).
- Composite key: SHA-256 of password, key file and YubiKey HMAC-SHA1 challenge-response, then the KDF (`KXC/keys/CompositeKey.cpp:85-171`). The challenge is the KDF seed, so the YubiKey is needed on every save. Key files: XML v1, XML v2 (default, with a typo-check hash), 32-byte binary, 64-char hex, or SHA-256 of any file (`KXC/keys/FileKey.cpp:59-127`).
- "Protected" values are XORed with a ChaCha20 stream inside the already encrypted payload (`KXC/format/KdbxXmlWriter.cpp:415-450`): memory obfuscation, not a security boundary.
- Size-leak mitigation: 64–512 random bytes in `KPXC_RANDOM_SLUG` on every save (`KXC/core/Database.cpp:320-322`); attachment dedup salted per DB or per shared group (`Kdbx4Writer.cpp:214-245`).

**Offline, sync and conflicts.** Offline by construction. On external change, KeePassXC offers Merge / Discard / Ignore; before saving it compares an MD5 of the first 1 KiB of the file (`KXC/core/Database.cpp:286-316`). Remote sync is user-defined download/upload commands (`KXC/gui/remote/RemoteSettings.h:30-35`). The merger (`KXC/core/Merger.cpp`) matches by UUID, resolves conflicts as **whole-entry LWW on `LastModificationTime` at second precision**, pushes the loser into history, unions histories (warning only when two snapshots share a timestamp, `:510-547`), honours `DeletedObjects` tombstones only in Synchronize mode (`:607-698`), and replaces DB custom data wholesale; the author's own TODO admits recycle bin, names and templates are not merged (`:702-704`). Concurrent edits to different fields of one entry lose one side (it survives only in history); clock skew picks the wrong winner.

**Sharing (KeeShare).** A group is exported into a second KDBX protected by a share password stored base64 in group custom data (`KXC/keeshare/KeeShare.cpp:82-110`). Signed containers exist, but import **ignores the signature file** (`KXC/keeshare/ShareImport.cpp:54-64`). No identities, no per-recipient keys, no revocation other than changing the password.

**Fields and item types.** No item types; see §4 for the complete field set. Entries have the five standard strings, arbitrary custom strings with a protected flag, attachments, tags, icons, colours, times and expiry, auto-type, custom data, and full history snapshots (default 10 items / 6 MiB, `KXC/core/Metadata.cpp:27-28`). Cards and identities only exist as `card_*` / `identity_*` strings created by the Bitwarden importer (`KXC/format/BitwardenReader.cpp:138-190`).

**SSH, passkeys, TOTP.**
- SSH: `KeeAgent.settings` XML attachment + key attachment or file path; the entry password is the key passphrase (`KXC/sshagent/KeeAgentSettings.cpp:237-470`). KeePassXC is a **client** of the system agent or Pageant: it adds keys with lifetime/confirm constraints and removes them on lock (`KXC/sshagent/SSHAgent.cpp:270-358, 503-585`). Once added, the private key lives in ssh-agent's memory. Key types include `sk-` FIDO keys (`OpenSSHKey.cpp:552-589`); generation via Botan (`OpenSSHKeyGen.cpp`).
- Passkeys: `KPEX_PASSKEY_*` attributes (`KXC/core/EntryAttributes.cpp:46-59`), ES256/EdDSA/RS256, sign counter always 0, fixed AAGUID (`KXC/browser/BrowserPasskeys.cpp:41, 184-186, 239-324`), used through KeePassXC-Browser.
- TOTP: `otp` otpauth URI preferred; reads KeeOtp, `TOTP Seed/Settings`, `TimeOtp-*`; 1–10 digits, 1–86400 s, SHA-1/256/512, Steam (`KXC/core/Totp.cpp:85-195`). No HOTP.

**Autofill.** Browser extension over native messaging with NaCl `crypto_box` (`KXC/browser/BrowserMessageBuilder.cpp:40-45`); auto-type keystroke sequences on desktop; freedesktop Secret Service export (`KXC/fdosecrets/`).

**Import/export.** KDBX 3.1/4.0/4.1, KDB import, unencrypted KeePass XML (full fidelity), CSV (lossy), HTML; imports 1PUX, OpVault, Bitwarden JSON (plain and encrypted), Proton Pass, passkey JSON (`KXC/gui/wizard/ImportWizard.h:44-54`). Health: zxcvbn, reuse, expiry (`KXC/core/PasswordHealth.cpp`); HIBP only as an offline file (`KXC/core/HibpOffline.cpp:27-105`).

**Strong.** An open, documented, battle-tested format with a large ecosystem, so KDBX import/export is an instant way in and out; offline by construction; Argon2id with tunable memory and an authenticated, index-bound block stream; the richest field model of all products studied (arbitrary protected strings, attachments, full history, tags, expiry, auto-type, references); cross-app conventions (`otp`, `KP2A_URL`, `KPEX_PASSKEY_*`, `KeeAgent.settings`); UUIDs and tombstones good enough to merge two copies; multi-factor composite key; size-leak mitigations.

**Weak.** Every change rewrites and re-uploads the whole file, attachments included; no concurrency control, so conflicts are settled by whole-entry LWW on client clocks at second precision, and metadata is not merged; no identities, per-user keys or revocation (KeeShare is a second file and a shared password, signatures unchecked); key files and YubiKey challenge-response are extra things to copy and lose, with no recovery; no item types, so cards, identities, SSH keys and passkeys are conventions each app reads differently; `LastAccessTime` / `UsageCount` updates create spurious changes; a single DB key and no AEAD, so a subset cannot be shared without exporting it into another container.

### 2.2 KeePass on phones: KeePassDX, Keepass2Android, KeePassium

All three read and write KDBX; each re-solves sync differently.

| | KeePassDX (Android, Kotlin) | Keepass2Android (Android, C#) | KeePassium (iOS, Swift) |
|---|---|---|---|
| Local copy | **None**: streams the SAF document (`KDX-APP/activities/helpers/ExternalFileHelper.kt:56-85`) | `CachingFileStorage`: local copy + hash of local + hash of remote at last sync, a three-way state on whole-file hashes (`K2A/Kp2aBusinessLogic/Io/CachingFileStorage.cs:78-176`) | `.latest` backup copy used as fallback when the file is unreachable (`KPM-Lib/DatabaseLoader.swift:561-574`) |
| On save conflict | **None**, overwrites; a dialog tells the user to merge by hand (`KDX-APP/activities/dialogs/DatabaseChangedDialogFragment.kt:35-80`) | prompt or automatic KeePassLib Synchronize merge (`K2A/Kp2aBusinessLogic/database/edit/SaveDB.cs:100-225`) | Overwrite / Save As / Cancel; merge is `assertionFailure("Not implemented")` (`keepassium/KeePassium/database/DatabaseSaving.swift:109-135`) |
| Offline edit safety | auto-save to the provider | write cache first, upload later (`CachingFileStorage.cs:424-459`) | **operation journal**: AutoFill edits saved as Codable operations in the Keychain and replayed (`KPM-Lib/db/transactions/DatabaseTransactionManager.swift:11-54`) |
| Biometrics protect | the master password (`KDX-APP/activities/MainCredentialActivity.kt:442-494`) | the master password, or a gate over the in-memory DB (QuickUnlock: last N characters, `QuickUnlock.cs:384-403`) | the composite or post-KDF key in an SE-encrypted Keychain item (`KPM-Lib/util/db-settings/DatabaseSettings.swift:16-127`) |
| Autofill | AutofillService, Credential Manager (passwords + passkeys, ML-DSA, PRF), keyboard IME (`KDX-APP/credentialprovider/…`) | AutofillService, KP2A keyboard (LatinIME fork), accessibility | AutoFill extension, QuickType identities; **120,000,000-byte memory cap** (`KPM-Lib/util/MemoryMonitor.swift:12`), warning at Argon2 ≥ 32 MiB |
| Extra URLs | `URL_n`, **not `KP2A_URL`** (no occurrence in the tree) | `KP2A_URL_n`, matched only by full-text search (`ShareUrlResults.cs:213-245`) | `KP2A_URL*` (`KPM-Lib/db/EntryField.swift:12-26`) |
| OTP | + HOTP (`HmacOtp-*`, `KDX-DB/otp/OtpEntryFields.kt:44-130`) | TOTP variants built in | TOTP variants, no HOTP |
| SSH | none | none (no KeeAgent plugin in the repo) | none |
| Import | KDBX only | KDBX | Apple CSV, Bitwarden, Enpass, 1PUX |

**Strong.** Real offline; K2A's base/local/remote hashes and KeePassium's operation journal are the right ideas; KeePassium's "remember the post-KDF key" lets the extension skip Argon2; KeePassDX's passkey support is the most complete (PRF, ML-DSA, privileged-browser allowlist, `KDX-APP/credentialprovider/passkey/util/PrivilegedAllowLists.kt`).

**Weak.** Three different conflict policies for one format; convention gaps (`URL_n` vs `KP2A_URL_n`); biometric unlock wraps the password itself in two of three; Keepass2Android's plugins receive all fields in plaintext, including protected ones (`K2A/keepass2android-app/pluginhost/PluginHost.cs:166-194`).

### 2.3 Strongbox

**Architecture.** iOS/macOS app (commit `c70fc7b`; the clone has no Xcode project or third-party code, so it reads but does not build). Opens KDBX 3.1/4.x, KDB and Password Safe v3 into one internal tree model (`SBX/model/DatabaseModel.m`, `SBX/model/NodeFields.h:38-139`), with stream-based decryption that keeps AutoFill memory low.

**Storage and crypto.** The format's own crypto. Argon2 default 16 MiB, parallelism 2 (`SBX/model/keepass/Argon2KdfCipher.m:25-33`), warning above 64 MiB for AutoFill.

**Offline and sync.** Every database has a local **encrypted working copy** that all opens read (`SBX/model/Sync/WorkingCopyManager.m:113-120`). A save writes a rolling backup first and refuses to save if that fails (`SBX/model/Sync/MacSyncManager.m:139-150`), then sets an `outstandingUpdateId`. Sync compares the **remote modification date only** (`SBX/model/Sync/SyncAndMergeSequenceManager.m:301-304`). Conflict strategy per database: Ask, AutoMerge, ForcePushLocal, ForcePullRemote; the Ask wizard adds Compare (dry-run diff) and **Sync Later** (`:582-637`). Merge is UUID-based whole-entry LWW with the loser in history (`DatabaseMerger.m:304-333`); **edit beats delete** (`:474-526`). Pushes are unconditional (Dropbox overwrite mode), so a write between pull and push is lost. Lazy sync opens the local copy instantly. Offline editing is a paid feature (`SBX/StrongBox/UnlockDatabaseSequenceHelper.m:181, 228`).

**Sharing.** Whole-file only; CloudKit sharing gives read/write of the entire database and its password (`SBX/model/cloudkit/CloudKitManager.swift:332-365`).

**Fields.** KeePass entries plus pwsafe fields (email, password history). Typed editors (credit card, SSH, passkey, TOTP) map onto custom fields; KeePass templates group. Excellent KeePassXC convention coverage (`SBX/StrongBox/Constants.m:45-74`).

**SSH, passkeys, TOTP.** Own macOS SSH agent: lists keys from unlocked databases, **keeps a public-key map so keys are listed while locked and a sign request prompts to unlock** (`SBX/macbox/ssh-agent/SSHAgentRequestHandler.swift:108-145, 209-247`), per-process approval with Touch ID and expiry (`:13-15, 58-105, 309-341`), sign log. Passkeys (iOS 17+/macOS 14+) as `KPEX_*` fields; one-time-code AutoFill (iOS 18).

**Mobile/autofill.** QuickType identity index written by the app, never passwords (`SBX/macbox/AutoFillManager.m:280-380`); the extension opens the local copy and never syncs; macOS "wormhole" asks the running app for one secret through the shared keychain instead of re-running the KDF (`SBX/macbox/Strongbox AutoFill/CredentialProviderViewController.m:116-260`). Convenience unlock stores **the master password** in a Secure-Enclave-wrapped keychain item, with biometrics checked in app code rather than by an access-control flag (`SBX/model/DatabaseUnlocker.m:301`, `SBX/model/SecretStore.m:420-433`). Apple Watch gets a plaintext subset (`SBX/Watch-App/Model/WatchEntry.swift:48-59`).

**Import/export.** Very broad importers: 1Password 1pif/1pux, Bitwarden, LastPass, Apple Passwords, iCloud Keychain, Enpass, Proton Pass, Secrets 4, mSecure, generic CSV, otpauth migration (`SBX/model/import/`), returning structured warnings. Rich audit: duplicate, **similar (Levenshtein)**, low entropy, HIBP with k-anonymity and padding, 2FA available (`SBX/model/DatabaseAuditor.h:25-35`); but the breached-account check sends the **email address in clear** to a Strongbox-run function (`SBX/model/DatabaseAuditor.m:971-985`).

**Strong.** Encrypted local copy as the source of truth; honest conflict UX (Compare, Sync Later); backup before every overwrite; edit beats delete; SSH agent UX; QuickType index; field compatibility; importers; duress actions (`SBX/StrongBox/DuressAction.h`).

**Weak.** Whole-file sync on modification dates with unconditional pushes; entry-level LWW on clocks; Password Safe merges cannot see deletes or moves (`DatabaseMerger.m:72-82`); file sharing only; master password stored for biometrics; email sent to a vendor; offline editing paywalled; Apple only.

### 2.4 Password Safe (pwsafe)

**Architecture.** Windows-first desktop app (MFC, wxWidgets ports) around one psafe3 file (commit `5302047`). Spec in `PWS/docs/formatV3.txt`, `formatV4.txt`.

**Storage and crypto.** psafe3: iterated SHA-256 key stretching (code minimum 327,680 iterations, `PWS/src/core/PWSfile.h:32`; not memory-hard), stored password check value H(P'), random K and L keys Twofish-ECB wrapped, records Twofish-256-CBC, HMAC-SHA256 over plaintext **field values only**, not types and lengths (`PWS/docs/formatV3.txt:41, 108-116`). V4 adds PBKDF2 key blocks per passphrase, HMAC over type and length, attachments with per-attachment keys, but is **still not the default** (`PWS/src/core/PWSfile.h:37-48`).

**Offline and sync.** One local file, a lock file, a file signature check (`PWS/src/core/PWSfile.h:195-217`). "Merge" matches entries by **Group+Title+User**, never overwrites, adds a `-merged-<timestamp>` copy on difference, and is undoable (`PWS/src/core/CoreOtherDB.cpp:447-930`). "Synchronize" is a manual one-way copy of chosen fields. No tombstones. Backup before every save (default on).

**Sharing.** None beyond the file and passphrase. V4's several key blocks unwrapping one data key is the conceptual precedent for per-member wrapped keys.

**Fields.** A versioned TLV record format (`PWS/src/core/Item.h:49-126`), unknown fields preserved: group path, title, user, notes, password, times (created, password modified, accessed, expiry, record modified), URL, auto-type, password history, **per-entry policy / named policy / symbol set**, expiry interval, run command, double-click actions, email, **protected (read-only) entry**, keyboard shortcut, TOTP fields, credit card fields, passkey fields, custom text fields with a sensitive flag, and **aliases (`[[uuid]]`, borrow the base password) and shortcuts (`[~uuid~]`, point at the whole entry)** (`PWS/src/core/CoreAlias.cpp:17-254`).

**SSH, passkeys, TOTP.** No SSH. Passkey fields defined in format 0x0310. TOTP in core (`PWS/src/core/TotpCore.cpp`). YubiKey HMAC-SHA1 with the passphrase as challenge.

**Import/export.** Plaintext/CSV, XML with schema, KeePass v1 TXT/CSV, V1/V2 files.

**Strong.** A small, well-specified, forward-compatible format; policies; aliases/shortcuts; protected entries; expiry intervals; conservative, undoable merge; backups.

**Weak.** Dated KDF and MAC; 32-bit times in V3; no sync, no sharing, no mobile apps of its own [GK: third-party apps exist, including Strongbox]; no browser autofill.

### 2.5 Bitwarden and Vaultwarden

**Architecture.** Client-server. TypeScript clients (web, extension, Electron desktop, CLI; `BWC`, commit `df96418`), a C# server (`BWS`, `5e68c1e`), and a Rust SDK shared through WASM and UniFFI (`BSDK`, `7d5b101`). Vaultwarden (`VW`, `6489552`) is a ~35 kLOC Rust reimplementation of the server (Rocket, Diesel).

**Storage and crypto.**
- Classic key tree: master password → KDF (salt = email) → master key → stretched key wraps a random **user key** → wraps an RSA-2048 private key, per-item cipher keys, per-attachment keys (`BSDK/bitwarden-crypto/src/keys/master_key.rs`). KDF PBKDF2 600,000 or Argon2id 32 MiB, t = 6, p = 4, but clients accept down to PBKDF2 5,000 / Argon2 16 MiB, and **the server dictates the parameters** (`BSDK/bitwarden-crypto/src/keys/kdf.rs:12-16, 163-178`).
- EncString formats: type 0 is AES-CBC **without MAC**, still decryptable (`BSDK/bitwarden-crypto/src/enc_string/symmetric.rs:48-49`); type 2 AES-CBC-HMAC; type 7 COSE (XChaCha20-Poly1305 / AES-GCM / XAES-GCM), preferred for new data.
- "V2" accounts: XAES-256-GCM user key, a signing key (ML-DSA-44 by default, Ed25519 supported), a signed public key and a **signed security state** whose monotonic version blocks server-driven downgrades (`BSDK/bitwarden-core/src/key_management/security_state.rs:32-48`). The encryption key is still RSA-2048 OAEP-SHA1 (`account_cryptographic_state.rs:331-351`).
- The new `safe` module (KEKs only wrap keys, fresh CEK per content, `PasswordProtectedKeyEnvelope`, `DataEnvelope`; `BSDK/bitwarden-crypto/src/safe/key_hierarchy/README.md`) is very close to what Kutup already does.
- **Moving from per-field EncStrings to whole-item blobs** (`BSDK/bitwarden-vault/src/cipher/README.md`): field-level encryption leaks structure and allows swapping; hence `uri_checksum` (`login.rs:58-84`).

**Offline and sync.** Full `GET /api/sync` of the whole vault, no delta (`BWS/Api/Vault/Controllers/SyncController.cs:95-96`), skipped when `/accounts/revision-date` is unchanged; SignalR push hints. Extension, desktop and CLI persist the encrypted vault; **the web vault keeps it in memory only** (`BWC/libs/state/src/core/state-definitions.ts:161, 231`). Offline unlock works (local authorization hash), but **edits are online only**: the API call comes first, then the local upsert (`BWC/libs/common/src/vault/services/cipher.service.ts:804-925`). Conflicts: the client sends `lastKnownRevisionDate`; the server rejects if off by more than 1 s (`BWS/Core/Vault/Services/Implementations/CipherService.cs:963-976`, `VW/src/api/core/ciphers.rs:457-462`); no merge. The SDK is moving storage into Rust with IndexedDB/SQLite backends of encrypted records (`BSDK/bitwarden-state/src/sdk_managed/`), the same shape as Kutup's plan.

**Sharing.** Organizations hold **one symmetric org key** RSA-wrapped to each confirmed member; collections and permissions (can view / view except passwords / edit / manage) are **server-enforced only**; every member can decrypt every org item the server sends, and "hide passwords" is a UI flag (`BSDK/bitwarden-vault/src/cipher/cipher.rs:347`). The "confirm" step fetches the member's public key from the server; fingerprint comparison is optional [code + GK]. **No org-key rotation exists**; removing a member is an ACL change (no rotation code was found in the server, clients or SDK). Emergency access (view / takeover after a wait, `BWS/Core/Auth/Entities/EmergencyAccess.cs:10-22`) hands the grantee the wrapped user key, released by the server. **Send**: text/file/item with the key in the URL fragment, max access count, expiry, optional password checked by the server (`BSDK/bitwarden-send/src/send.rs`).

**Fields.** Eight types: Login, SecureNote, Card, Identity, SshKey, and new BankAccount, DriversLicense, Passport (`BSDK/bitwarden-vault/src/cipher/cipher.rs:93-102`); CXF also models Wi-Fi and API key. Custom fields text / hidden / boolean / **linked** (points at a built-in field for autofill, `BSDK/bitwarden-vault/src/cipher/linked_id.rs:12-72`). URIs with six match types (Domain, Host, StartsWith, Exact, RegEx, Never; `login.rs:29-35`). Password history **max 5** entries, including changed hidden fields (`password_history.rs:15-25`). Reprompt, trash, archive. Missing vs KeePassXC [GK]: tags, icons, per-entry expiry, auto-type, full history snapshots, arbitrary protected attributes.

**SSH, passkeys, TOTP.** SshKey type stores the OpenSSH private key **unencrypted inside the EncString**; import decrypts passphrase-protected keys (`BSDK/bitwarden-ssh/src/import.rs:163-170`); generation Ed25519 / RSA-3072/4096 with the RustCrypto `ssh-key` crate (`generator.rs:17-45`). Desktop runs its own Rust agent: in-memory encrypted keystore, **approval for every signature**, peer process info, SSHSIG namespace (git signing), `session-bind@openssh.com` host verification, remember-until-lock per host (`BWN/ssh_agent/src/`, `BWC/apps/desktop/src/autofill/services/ssh-agent.service.ts:461-560`). No agent without the desktop app [GK: none in the CLI]. Passkeys stored on the login with explicit fields, authenticator from 1Password's `passkey-rs` (`BSDK/bitwarden-fido/src/lib.rs:7`). TOTP base32 / otpauth / `steam://` (`BSDK/bitwarden-vault/src/totp.rs`).

**Mobile/autofill.** Mobile repos not cloned; [GK]: Android Autofill Framework + Credential Manager + accessibility fallback, iOS AutoFill extension, SDK via UniFFI (`BSDK/bitwarden-uniffi`). PIN unlock: user key in an Argon2id envelope keyed by the PIN, either on disk (works after restart, allows offline brute force of a short PIN) or in memory only (`BSDK/bitwarden-core/src/key_management/pin_lock_system.rs:22-33`).

**Import/export.** CSV, JSON, ZIP with attachments, encrypted JSON "account restricted" (breaks on key rotation) or **password-protected** (portable; `BSDK/bitwarden-exporters/src/encrypted_json.rs:28-60`), and **CXF** (FIDO Credential Exchange Format, `BSDK/bitwarden-exporters/src/cxf/`). About 80 importers (`BWC/libs/importer/src/importers/`), and a new Rust KDBX importer using the `keepass` crate (`BSDK/bitwarden-importers/src/importers/kdbx.rs:1-51`).

**Vaultwarden.** Useful as a compact schema: opaque encrypted JSON plus a few plaintext ACL columns (`VW/src/db/schema.rs`), per-user favourites and folders as join tables, collection ACL joins, an emergency-access state machine with a scheduled job, Send expiry jobs, SignalR-compatible push. No V2 crypto (`VW/src/db/models/user.rs:269-285`).

**Strong.** One Rust crypto core on every platform; per-item and per-attachment keys; signed security state; rich types and linked fields; the best SSH agent design; portable encrypted export and CXF; audited [GK].

**Weak.** Server-chosen KDF parameters; unauthenticated legacy EncString type; field-level encryption; server-distributed public keys with optional fingerprint checks; no org-key rotation; UI-only "hide passwords"; no offline edits, no delta sync, no web offline cache; account-restricted exports break on rotation. [GK, unverified] An ETH Zurich analysis (reported around February 2026) of Bitwarden, LastPass and Dashlane under a malicious server is said to have demonstrated attacks along these lines (key escrow via organizations or account recovery, KDF downgrade, item integrity); details were not checked and should be verified before being relied on.

### 2.6 Proton Pass

**Architecture.** Client-server. Shared TS logic for web, extension and Electron desktop (`PPW`, in WebClients `4c408125`), native Android (`PPA`, `9565065`) and iOS (`PPI`, `0b0fc36`), a shared Rust core (`@protontech/pass-rust-core`, `PPW/package.json:43`) for passkeys and invite signatures.

**Storage and crypto.** user key (OpenPGP) → **share key = vault key** (random AES-256-GCM, OpenPGP-encrypted *and signed* to the user; the client requires a valid self-signature, so the server cannot inject a vault key, `PPW/lib/crypto/processes/share/open-share-key.ts:14-34`) → optional folder keys → **item key** per item → item content (protobuf, AES-GCM). Every AES-GCM call carries a domain-separation tag as AAD (`PPW/types/crypto/pass-types.ts:3-21`). Moving an item re-wraps only its key (`PPW/lib/crypto/processes/item/move-item.ts:18-35`). Item content is capped at ~40 KB (`PPW/lib/crypto/utils/validators.ts:5-14`). Keys carry a `KeyRotation` number and the server has `NOT_LATEST_KEYS` errors (`PPW/lib/api/errors.ts:9-27`), but **no client in the clones performs a rotation**.

**Offline and sync.** Web/extension: an encrypted cache of the whole state; opt-in offline mode derives `offlineKD` with Argon2 from the password to unwrap the cache key (`PPW/lib/cache/crypto.ts:61-146`); setup needs an online password check. **Offline is read-only**: no edit queue (`PPW/store/sagas/client/hydrate.saga.ts:137-140`). Sync v2 is a per-user event cursor (`PPW/lib/sync/v2/user-events.requests.ts:4-14`). Conflicts: `LastRevision` on edit, `NOT_LATEST_REVISION` on stale writes, no merge; server revisions serve as item history. Android keeps server ciphertext plus a local Keystore-encrypted copy in Room (`PPA/pass/data/impl/.../db/entities/ItemEntity.kt:70-125`); iOS uses Core Data and processes key-rotation events before items (`PPI/LocalPackages/Client/Sources/Client/EventLoop/EventSynchronizer.swift:28-45`).

**Sharing.** One share row per member per target, roles Manager / Write / Read plus Owner, **per-membership `ExpireTime`**, `CanAutoFill`, hidden flag (`PPW/types/api/pass.ts:1363-1407`, `PPW/types/data/shares.ts:12-16`). Vault invite: every vault-key rotation encrypted to the invitee's public key, signed with a context; the invitee accepts by **re-encrypting to its own key, self-signed** (`PPW/lib/crypto/processes/invite/reencrypt-invite-keys.ts:16-38`). Item share: the recipient holds just the item keys (`PPW/lib/invites/invite.requests.ts:105-135`). **Invites for people without an account**: a signed binding of email to the current share key; after sign-up a manager "promotes" the invite by encrypting to the new key (`PPW/lib/crypto/pass-crypto.ts:554-593`). Groups via OpenPGP forwarding. **Secure links**: random link key in the URL fragment wraps the item key; the link key is wrapped under the item key so the owner can list links; expiry and max reads (`PPW/lib/crypto/processes/secure-link/create-secure-link.ts:14-32`). Personal access tokens wrap selected vault keys for CLI/agents (`PPW/lib/crypto/processes/access-token/`). Weaknesses: recipients' public keys come from Proton's key server with **no verification UI**, and revocation is a server row delete (`PPW/lib/shares/share.requests.ts:66-70`).

**Fields.** `item-v1.proto`: note, login (email, username, password, URLs, `totp_uri`, passkeys, autofill URLs with seven match modes), alias, credit card, identity (very detailed), SSH key, Wi-Fi, custom; custom sections of extra fields typed text / hidden / TOTP / timestamp; Android allowed apps with signing-cert hashes (`PPW/types/protobuf/protos/item-v1.proto`). Missing vs KeePassXC: tags, per-entry expiry, icons per item, history export, auto-type, protected flag per string.

**SSH, passkeys, TOTP.** SSH key type; the desktop app runs a Rust agent on `russh` that only checks "app unlocked", no per-use dialog (`PPD/native/napi/src/ssh_agent/mod.rs:76-86, 326-332`). Passkeys are an **opaque blob** from the Rust core inside the login (`Passkey.content`), so they travel with shared items but are not portable as fields. TOTP in JS, no Steam on web.

**Aliases.** SimpleLogin-backed; the alias address lives server-side; one call creates login + alias (`PPW/lib/alias/alias.requests.ts`, `PPW/lib/items/item.requests.ts:114-146`).

**Monitor.** Reused, weak, missing 2FA, breached passwords via k-anonymity with 6-hex prefixes and padding (`PPW/lib/monitor/compromised-password.request.ts:1-50`), dark-web email monitoring server-side.

**Import/export.** Import from 18 sources, KeePass only as XML (`PPW/lib/import/types.ts:7-26`); export CSV, JSON, ZIP, or OpenPGP passphrase-encrypted with iterated S2K (`PPW/lib/crypto/utils/export.ts:5-22`).

**Strong.** Clean three-level key tree with AAD tags; self-signed share keys; deferred invites for non-users; item shares; secure links; roles with expiry; one Rust core; anti-phishing autofill (cross-origin iframe exclusion, regex warnings, Android cert pinning).

**Weak.** No key rotation in practice; unverified recipient keys; offline read-only; no merge; 40 KB item cap; KeePass-incompatible fields; old export S2K.

### 2.7 Passbolt

**Architecture.** Team password manager: PHP/CakePHP server (`PB`, `8ff0944`, v5.16.0 from 2026-09-16, `PB/RELEASE_NOTES.md:3`) and a browser extension holding all client crypto (not cloned; client claims are [GK]).

**Storage and crypto.** OpenPGP throughout. **One secret row per (resource, user)**, encrypted to that user's key (`PB/src/Model/Entity/Secret.php:25-39`). v5 encrypts resource metadata under a personal or **org-wide shared metadata key**; in "user-friendly" mode the server holds a copy of that key and shares it with new users itself (`PB/plugins/PassboltCe/Metadata/src/Service/MetadataKeyShareDefaultService.php:44-86`), which is not zero-knowledge. Mutual GPGAuth login (`PB/src/Authenticator/GpgAuthenticator.php`).

**Offline and sync.** Online by design; offline mode (5.16.0) is opt-in per item, with admin caps: session 300 s default, retention 7 days, 1,000 items (`PB/plugins/PassboltCe/OfflineMode/src/Model/Dto/OfflineSettingsDto.php:22-42`).

**Sharing.** ACLs on resources and folders for users and groups, READ / UPDATE / OWNER (`PB/src/Model/Entity/Permission.php:44-46`). Sharing = the sharer's browser re-encrypts the secret for each new recipient; the server deletes rows of users who lost access and asserts every user with access has a secret (`PB/src/Service/Secrets/SecretsUpdateSecretsService.php:197-228`). Group adds need a group manager to re-encrypt every reachable secret (`PB/src/Service/Groups/GroupsUpdateDryRunService.php:92-107`). Cost is O(users × resources). **Password expiry on access loss** marks resources expired when someone who had viewed them loses access (`PB/plugins/PassboltCe/PasswordExpiry/…/PasswordExpiryExpireResourcesService.php:28-36`).

**Fields.** Resource types with JSON schemas: password, description, TOTP, custom fields (text / password / boolean / number / uri), note, **PIN code** (`PB/plugins/PassboltCe/ResourceTypes/src/Model/Definition/SlugDefinition.php`). No SSH, passkey or card types as of 5.16. KeePass icon set in metadata.

**Import/export.** KDBX and CSV, done in the extension.

**Strong.** Revocation is real for future changes; no shared symmetric key; fine-grained ACLs, access logs, expiry on access loss; KDBX.

**Weak.** O(users × resources) ciphertexts and re-encryption on every change; users manage OpenPGP keys; recovery needs Enterprise escrow; server-distributed metadata key in the default mode; offline arrived late and capped; no passkeys, SSH or aliases.

---

## 3. Comparison tables

### 3.1 Crypto and KDF

| Product | Password KDF (default) | Data cipher | Integrity | Key hierarchy |
|---|---|---|---|---|
| KeePassXC / KDBX 4 | Argon2d/id 64 MiB, 10 it. (AES-KDF option) | AES-256-CBC / ChaCha20 / Twofish | HMAC-SHA256 block stream | one DB key |
| KeePassium | Argon2 8 MiB default | as KDBX | as KDBX | one DB key |
| Strongbox | Argon2 16 MiB, p = 2 | as KDBX / psafe3 | as format | one DB key |
| Password Safe v3 | iterated SHA-256, ≥ 327,680 | Twofish-CBC | HMAC over values only | K/L keys under P' |
| Bitwarden | PBKDF2 600k or Argon2id 32 MiB t = 6 p = 4; **server-chosen**, minimums low | AES-CBC-HMAC, moving to XChaCha20/XAES-GCM (COSE) | EncMAC / AEAD; legacy type 0 unauthenticated | user key → org key / item keys → attachment keys |
| Proton Pass | (account login, SRP) + Argon2 for offline key | AES-256-GCM with AAD tags | AEAD + OpenPGP signatures on share keys | user key → vault key → (folder key) → item key |
| Passbolt | OpenPGP key passphrase [GK] | OpenPGP | OpenPGP | per-user secret copies; shared metadata key |
| **Kutup today** | Argon2id 64 MiB, t = 3, p = 1, fixed V1 (`crates/kutup-crypto/src/kdf.rs:24-26`) | XChaCha20-Poly1305 | AEAD with authenticated suite, purpose, profile | random master key; Drive collection epochs → file key generations |

### 3.2 Storage and sync model

| Product | Unit of storage | Change detection | Delta sync | Push |
|---|---|---|---|---|
| KeePassXC | whole file | MD5 of first 1 KiB + file watcher | no | no |
| KeePassDX | whole file (no local copy) | mtime + size | no | no |
| Keepass2Android | whole file + cache | SHA-256 vs base | no | no |
| KeePassium | whole file + `.latest` | SHA-512 vs hash at load | no | no |
| Strongbox | whole file + working copy | remote mod date | no | CloudKit subscription |
| Password Safe | whole file | file signature | no | no |
| Bitwarden | per item (server) | `/accounts/revision-date` | **no** (full `/sync`) | SignalR / APNs / FCM |
| Proton Pass | per item | event cursor | yes | events [GK for mobile push] |
| Passbolt | per resource × user | [GK] | [GK] | [GK] |
| **Kutup Pass (proposed)** | per item record | server revision + account cursor | yes | WebSocket hint, then pull |

### 3.3 Offline

| Product | Offline read | Offline write | Offline unlock |
|---|---|---|---|
| KeePass family, Password Safe | yes | yes (local file) | yes |
| Strongbox | yes | yes, **Pro only** | yes |
| Bitwarden | yes, except the web vault | **no** | yes (local hash) |
| Proton Pass | yes (opt-in on web) | **no** | yes with offline mode (Argon2) |
| Passbolt | opt-in per item, ≤ 7 days, capped | [GK] almost certainly no | [GK] |
| **Kutup Pass (proposed)** | yes, full replica | **yes, outbox** | yes |

### 3.4 Conflict handling

| Product | Granularity | Rule | Loser kept? |
|---|---|---|---|
| KeePassXC | whole entry | LWW on client clock, 1 s precision | in history |
| KeePassDX | whole entry (manual merge) | overwrite on save | no, unless merged |
| Keepass2Android | whole entry | KeePassLib Synchronize (LWW) | in history |
| KeePassium | whole file | overwrite or save-as | separate file |
| Strongbox | whole entry | LWW; edit beats delete; Ask / Compare / Sync Later | in history |
| Password Safe | whole entry | never overwrite; `-merged-<time>` copy | as duplicate |
| Bitwarden | whole item | reject stale (± 1 s) | user redoes edit |
| Proton Pass | whole item | reject stale revision | user redoes edit |
| **Kutup Pass (proposed)** | **per field** | three-way merge against base revision; edit beats delete | in history, item flagged for review |

### 3.5 Sharing and revocation

| Product | Unit | Key distribution | Recipient verification | Removal | Key rotation |
|---|---|---|---|---|---|
| KeePassXC KeeShare | group → separate file | shared password | signature ignored on import | change password | manual |
| Strongbox | whole database | file + password (CloudKit share) | none | none | none |
| Password Safe | whole file | passphrase | none | none | none |
| Bitwarden | org / collection | org key RSA-wrapped per member | optional fingerprint | ACL only | **none** |
| Proton Pass | vault, item, (folder) | vault/item keys encrypted per member, signed | none in UI | server row delete | field exists, **not performed** |
| Passbolt | resource / folder | per-user re-encryption | OpenPGP keys, server-listed | delete rows; future edits exclude | n/a (per-user copies) |
| **Kutup Pass (proposed)** | vault and item | HPKE named-share envelopes, signed | **identity pins + safety numbers** | ACL **and** new epoch | **yes, lazy re-wrap; item key rotation for item shares** |

### 3.6 Item types and fields

| | KeePassXC | Strongbox | pwsafe | Bitwarden | Proton | Passbolt |
|---|---|---|---|---|---|---|
| Typed items | no | editors only | no | 8 types | 8 types | resource types |
| Custom fields | any, protected flag | yes | yes, sensitive flag | text/hidden/bool/linked | text/hidden/TOTP/timestamp | text/password/bool/number/uri |
| Attachments | in file | yes | V4 | yes (per-attachment key) | separate files | no |
| Tags | yes | yes | no | no (folders) | no | [GK] tags in EE |
| Icons, colours | yes | yes | no | favicon | vault icon only | KeePass icon set |
| Expiry | yes | yes | date + interval | no | no | yes (policy) |
| History | full snapshots | full + passwords | passwords | 5 passwords | server revisions | secret revisions |
| Auto-type | yes | yes | yes | no | no | no |
| References | `{REF:…}` | yes | aliases/shortcuts | linked fields (built-in only) | no | no |
| Password policy per item | no | no | **yes** | no | org policy | no |

### 3.7 SSH agent

| | KeePassXC | Bitwarden desktop | Proton desktop | Strongbox (macOS) |
|---|---|---|---|---|
| Agent | uses system agent / Pageant | own, Rust | own, Rust (`russh`) | own, Obj-C |
| Private key leaves the app | **yes** | no | no | no |
| Per-use approval | only via agent confirm (askpass) | **yes**, with process, host, git namespace | no ("app unlocked") | yes, per process, with expiry |
| Lists keys while locked | no | no | no | **yes** |
| Forwarding / git aware | no | **yes** | no | no |
| Windows | Pageant + OpenSSH pipe | OpenSSH pipe | OpenSSH pipe | n/a |

### 3.8 Passkeys

| | Storage | Portable fields | Authenticator | Platforms |
|---|---|---|---|---|
| KeePassXC | `KPEX_PASSKEY_*`, PKCS#8 PEM | yes | own (ES256/EdDSA/RS256), counter 0 | browser extension |
| KeePassDX / KeePassium / Strongbox | same `KPEX_PASSKEY_*` | yes | own | Credential Manager (+ML-DSA, PRF) / ASCredentialProvider |
| Bitwarden | explicit fields on login | yes (+CXF) | `passkey-rs` | extension, mobile [GK], macOS ext., Windows plugin |
| Proton Pass | opaque `content` bytes | **no** | Rust core | extension, Android, iOS |
| Passbolt | none | — | — | — |

### 3.9 TOTP

| | Storage | Algorithms | Steam | HOTP |
|---|---|---|---|---|
| KeePassXC | `otp` URI + 3 legacy forms | SHA-1/256/512, 1–10 digits | yes | no |
| KeePassDX | as KeePassXC + `HmacOtp-*` | same | yes | **yes** |
| Strongbox | all KeePass forms; writes several | same | yes | [not checked] |
| Password Safe | binary secret + config fields | SHA-1 only defined | no | core has `hotp.h` |
| Bitwarden | base32 / otpauth / `steam://` | SHA-1/256/512 | yes | no [GK] |
| Proton Pass | `totp_uri` + extra TOTP fields | via `otpauth` lib | no on web | no |
| Passbolt | TOTP object, 6–8 digits | yes | no | no |

### 3.10 Autofill and extension

| | Browser | Android | iOS |
|---|---|---|---|
| KeePassXC | KeePassXC-Browser via native messaging | — | — |
| KeePassDX | — | Autofill + Credential Manager + IME | — |
| Keepass2Android | — | Autofill + keyboard + accessibility | — |
| KeePassium | — | — | AutoFill extension (120 MB cap) |
| Strongbox | extension → native messaging → app | — | AutoFill extension, QuickType index |
| Bitwarden | own extension, inline menu, WebAuthn interception | Autofill + Credential Manager + accessibility [GK] | AutoFill extension [GK] |
| Proton Pass | own extension, ML form detection, no cross-origin iframes | Autofill + Credential Manager | AutoFill extension |
| Passbolt | own extension [GK] | app [GK] | app [GK] |

### 3.11 Import and export

| | Lossless own export | Encrypted portable export | KDBX | CXF | Importers |
|---|---|---|---|---|---|
| KeePassXC | KDBX / XML | KDBX | native | no | 6 |
| Strongbox | file copy | the database file | native | no | ~13 |
| Password Safe | psafe3 / XML | psafe3 | no | no | few |
| Bitwarden | JSON / ZIP | **password-protected JSON** | import (Rust, new); KeePass XML/CSV | **yes** | ~80 |
| Proton Pass | JSON / ZIP | OpenPGP S2K | KeePass **XML** import only | no | 18 |
| Passbolt | [GK] | [GK] | KDBX in extension | no | KDBX, CSV |
| **Kutup Pass (proposed)** | JSON archive | Argon2id + XChaCha20 archive **and KDBX 4.1** | **lossless read/write** | later | checklist in §5.13 |

### 3.12 Licences: what Kutup may copy and what it should only read

Kutup is **AGPL-3.0-only** (`Cargo.toml:21`, `LICENSE`). Compatibility statements below are [GK]; get them confirmed before copying code.

| Repo | Licence | Copy into Kutup? |
|---|---|---|
| keepassxc | GPL-2 or GPL-3 (`keepassxc/COPYING`) | Possible under the GPL-3 option (GPL-3 + AGPL-3 combine, §13 of each). Test databases in `keepassxc/tests/data/` are useful as a parity corpus |
| keepassdx, keepassium, keepass2android | GPL-3.0 | Possible |
| strongbox | AGPL-3.0 | Possible (same licence) |
| pwsafe | Artistic-2.0 | Possible [GK: GPL-compatible]; the format specs are the useful part |
| bitwarden-clients | GPL-3.0, except `bitwarden_license/` | GPL parts possible; `bitwarden_license/` not |
| bitwarden-server | AGPL-3.0, except `bitwarden_license/` | AGPL parts possible |
| bitwarden-sdk-internal | per crate `GPL-3.0-only OR LicenseRef-Bitwarden-SDK` (e.g. `bitwarden-crypto/Cargo.toml:14`); `bitwarden_license/*` SDK licence only | Only under the GPL-3.0 option; **never** under the SDK licence (it forbids use with non-Bitwarden software); `bitwarden_license/*` is off limits |
| vaultwarden | AGPL-3.0-only | Possible |
| proton-pass-android, proton-pass-ios, WebClients | GPL-3.0 | Possible |
| passbolt-api | AGPL-3.0 | Possible |

Recommendation: treat all of them as design references and write Kutup's own Rust. The useful dependencies are separate, permissively licensed crates [GK]: `ssh-key` (RustCrypto), `passkey-rs` (1Password), `keepass` (KDBX), `zxcvbn`; check their licences when adopting.

---

## 4. Field model

### 4.1 Principles

1. **Typed items on top, KDBX underneath.** Users see logins, cards, SSH keys; the codec sees strings, binaries and custom data. Each Kutup field has a fixed KDBX mapping, and anything KDBX has that Kutup does not model is kept in a per-item **`kdbx` extension bag** and written back unchanged.
2. **Lossless means:** import a KDBX 4.1 file, export it without edits, and the XML is semantically equal except for (a) file crypto parameters chosen at export, (b) `KPXC_RANDOM_SLUG`, (c) values Kutup deliberately regenerates and lists. The proof is a test that round-trips every database in `keepassxc/tests/data/` and a set of files written by KeePassDX, KeePassium and Strongbox.
3. **Read every variant, write the canonical one plus compatibility copies.** Import reads all TOTP forms, both passkey username keys, and both extra-URL conventions; export writes `otp` + `TimeOtp-*`, and `KP2A_URL_n` + `URL_n`.
4. **Stable field ids.** Custom fields carry a random id so the three-way merge (§5.5) can tell "renamed" from "deleted and added".

### 4.2 Proposed item types

| Type | Specific fields | Closest precedent |
|---|---|---|
| `login` | username, email, password, `urls[]` {url, match}, `totp`, `passkeys[]`, `android_apps[]` {package, cert hashes}, autofill options | Bitwarden Login, Proton ItemLogin |
| `note` | (body is `notes`) | all |
| `card` | holder, brand, number, CVV, expiry, valid from, PIN, issue number | Bitwarden Card, Strongbox `CreditCardData.swift:4-17`, pwsafe 0x1c-0x1f |
| `identity` | Proton's personal/address/contact/work sections plus SSN, passport, licence numbers | Proton ItemIdentity, Bitwarden Identity |
| `ssh_key` | private key (OpenSSH, plain inside the sealed blob), public key, fingerprint, comment, key type, optional passphrase, agent policy | Bitwarden SshKey + KeeAgent.settings |
| `wifi` | SSID, password, security | Proton ItemWifi, CXF |
| `bank_account` | bank, holder, type, number, routing, branch, SWIFT, IBAN, PIN, phone | Bitwarden BankAccount |
| `passport`, `drivers_licence` | Bitwarden's fields | Bitwarden Passport / DriversLicense |
| `api_key` | key, secret, endpoint, expiry | CXF `api_key` |
| `pin` | PIN (4–12 digits) | Passbolt `v5-pin-code` |
| `custom` | sections only | Proton ItemCustom |
| `alias` | Kutup Mail alias id + note (§5.11) | Proton ItemAlias |

**Common envelope (every type):** name; notes (Markdown allowed); tags; folder; icon (KeePass built-in id 0–68, custom icon ref, or favicon); foreground/background colour; `custom_fields[]` {id, name, value, kind: text | hidden | totp | url | email | phone | number | boolean | date | reference}; `sections[]`; attachments; `expires_at`; `rotate_every_days`; password policy (inline or named); `locked` (pwsafe "protected"); `exclude_from_monitor`; `reprompt`; auto-type {enabled, obfuscation, default sequence, associations[]}; `custom_data` map (namespaced); `kdbx` extension bag; history; created/modified times (client-claimed, inside the blob). Per-user, not shared: favourite, last used, usage count, folder placement in shared vaults (a separate per-user encrypted record, like Bitwarden's per-user favourite/folder columns `BWS/Core/Vault/Entities/Cipher.cs:21-22`).

### 4.3 KDBX 4.1 → Kutup mapping

**Entry-level fields** (`KXC/format/KdbxXmlWriter.cpp:392-520`):

| KDBX | Kutup | Notes |
|---|---|---|
| `UUID` | item id | reused on import so re-import de-duplicates |
| `String Title` | `name` | |
| `String UserName` | `login.username` | |
| `String Password` | `login.password`; `ssh_key.passphrase` for KeeAgent entries; `card`/others: `kdbx` bag | |
| `String URL` | `login.urls[0]` | |
| `String Notes` | `notes` | |
| other `String` {Key, Value, Protected} | `custom_fields[]`, Protected → `hidden` | unless a convention below claims the key |
| `Binary` {Key, Ref} | attachments | separate encrypted blobs (§5.4) |
| `IconID`, `CustomIconUUID` | `icon` | custom icons become vault-level icon records with name and mtime (4.1) |
| `ForegroundColor`, `BackgroundColor` | colours | |
| `OverrideURL` | `kdbx.override_url` | shown read-only; never executed from the web |
| `Tags` | `tags` | `;`/`,` split |
| `Times/CreationTime` | `created_at` | |
| `Times/LastModificationTime` | `modified_at` | client-claimed; sync uses server revisions |
| `Times/LastAccessTime`, `UsageCount` | per-user local record; imported values kept in `kdbx` bag | not synced: they cause write amplification and conflicts (§2.1) |
| `Times/LocationChanged` | derived from move operations; imported value kept | |
| `Times/ExpiryTime` + `Expires` | `expires_at` | |
| `QualityCheck=False` (4.1) | `exclude_from_monitor` | legacy `KnownBad` read too |
| `PreviousParentGroup` (4.1) | trash restore target | |
| `AutoType` {Enabled, DataTransferObfuscation, DefaultSequence, Association{Window, KeystrokeSequence}} | `autotype` | stored for desktop users; unused on web/mobile |
| `CustomData` {Key, Value, LastModificationTime} | `custom_data` | |
| `History` | history snapshots (§5.5) | default limits 10 items / 6 MiB, as KeePassXC (`KXC/core/Metadata.cpp:27-28`) |

**Attribute conventions** (stored as ordinary strings or attachments in KDBX, typed in Kutup):

| Convention | Kutup | Sources |
|---|---|---|
| `KP2A_URL`, `KP2A_URL_n`; `URL_n` (KeePassDX) | `login.urls[]` | `KXC/core/EntryAttributes.cpp:43`, `KDX-DB/model/EntryInfo.kt:416` |
| `AndroidApp`, `AndroidApp_n`, `AndroidApp Signature` | `login.android_apps[]` | `KDX-DB/model/AppOriginEntryField.kt:30-145` |
| `otp` (otpauth URI or KeeOtp query) | `login.totp` | `KXC/core/Totp.cpp:85-155` |
| `TOTP Seed` + `TOTP Settings` | `login.totp` (read) | `KXC/core/Totp.h:71-72` |
| `TimeOtp-Secret[-Hex/-Base32/-Base64]`, `-Algorithm`, `-Length`, `-Period` | `login.totp` (read; written on export) | `KXC/core/Totp.h:75-78`, `SBX/StrongBox/Constants.m:45-74` |
| `HmacOtp-Secret*`, `HmacOtp-Counter` | `login.hotp` | `KDX-DB/otp/OtpEntryFields.kt:44-130` |
| `KPEX_PASSKEY_USERNAME`, `_CREDENTIAL_ID`, `_PRIVATE_KEY_PEM`, `_RELYING_PARTY`, `_USER_HANDLE`, `_FLAG_BE`, `_FLAG_BS`; `_GENERATED_USER_ID`, `KPXC_PASSKEY_USERNAME`; `KPEX_PASSKEY_PRF` (KeePassDX) | `login.passkeys[]` | `KXC/core/EntryAttributes.cpp:46-59`, `KDX-DB/model/PasskeyEntryFields.kt:13-24` |
| attachment `KeeAgent.settings` + key attachment (or file path) | `ssh_key` type + agent policy | `KXC/sshagent/KeeAgentSettings.cpp:237-470` |
| CustomData `KeePassXC-Browser Settings` {Allow, Deny, Realm} | autofill allow/deny hosts | `KXC/browser/BrowserEntryConfig.cpp:29, 88-112` |
| `BrowserSkipAutoSubmit`, `BrowserHideEntry`, `BrowserOnlyHttpAuth`, `BrowserNotHttpAuth`, `BrowserOmitWww`, `BrowserRestrictKey` | login autofill options | `KXC/browser/BrowserService.cpp:65-70` |
| CustomData `KPEX_DoNotSuggestForAutoFill` (Strongbox) | autofill: never suggest | `SBX/StrongBox/Constants.m:63` |
| `card_*`, `identity_*` strings (KeePassXC's Bitwarden import) | `card`, `identity` | `KXC/format/BitwardenReader.cpp:138-190` |
| `_etm_*` template keys (KeePassDX) | type hints | `KDX-DB/database/element/template/TemplateEngineCompatible.kt:405-430` |
| `_EXEC_CMD` | `kdbx` bag | `KXC/core/EntryAttributes.cpp:42` |
| `{REF:P@I:<uuid>}` and other `{REF:…}` | `reference` custom field / item reference (§4.4) | `KXC/core/Entry.cpp:111-134, 1322-1475` |
| placeholders `{TITLE}`, `{USERNAME}`, `{S:…}`, `{DT_*}`, `{T-CONV:…}` … | stored verbatim; only `{REF}` is resolved by Kutup | `KXC/core/EntryPlaceholders.h:30-67` |

On export, a Kutup item type that KDBX cannot express is written as the closest convention plus a `KUTUP_TYPE` custom data key (and the type's fields as namespaced strings, e.g. `card_number`), so a re-import restores the type exactly and other KeePass apps still show readable fields.

**Groups** (`KXC/format/KdbxXmlWriter.cpp:308-350`): UUID, Name, Notes, Tags (4.1), icon, Times, IsExpanded, DefaultAutoTypeSequence, EnableAutoType / EnableSearching (tri-state), LastTopVisibleEntry, CustomData, PreviousParentGroup → **folders** inside a vault (encrypted folder records), with the KeePass-only attributes in the folder's `kdbx` bag. Sibling order is kept as a sort key.

**Database metadata** (`KXC/format/KdbxXmlWriter.cpp:136-182`):

| KDBX Meta | Kutup |
|---|---|
| DatabaseName, Description, DefaultUserName, Color (+Changed times) | vault metadata record |
| MemoryProtection flags | defaults for which standard fields are `hidden` |
| CustomIcons | vault icon records |
| RecycleBinEnabled / UUID | trash (server-side retention) |
| EntryTemplatesGroup | custom templates (user-defined item layouts) |
| HistoryMaxItems / HistoryMaxSize, MaintenanceHistoryDays | vault history policy |
| MasterKeyChangeRec / Force | export-file setting only |
| `Root/DeletedObjects` | imported as tombstones when merging a KDBX into an existing vault |
| Meta CustomData `KPXC_BROWSER_*`, `KPXC_REMOTE_SYNC_SETTINGS`, `FDO_SECRETS_EXPOSED_GROUP` | kept in the vault's `kdbx` bag; `KPXC_BROWSER_*` (pairing keys of one machine) dropped by default with a notice |
| `KPXC_RANDOM_SLUG` | regenerated |
| Generator, HeaderHash, SettingsChanged | regenerated |

**What cannot be lossless, by design:** key files and YubiKey challenge-response belong to a file, not to a Kutup vault; Kutup asks for them on import and offers them again on export. KDBX 3.1 and KDB are import-only.

### 4.4 Password Safe extras worth keeping

| pwsafe | Kutup | KDBX export |
|---|---|---|
| Alias (`[[uuid]]`, borrows the base password) | `reference` field `ref(item_id, "password")`; base shows "used by N items" | `{REF:P@I:<uuid>}` |
| Shortcut (`[~uuid~]`, whole entry) | a pinned reference item | `{REF:…}` per field |
| Per-entry policy, named policies, symbol set (0x10, 0x16, 0x18) | vault-level named policies + per-item override; used by the generator and the monitor ("violates this site's policy") | `custom_data` `pwsafe.policy*` |
| Expiry interval (0x11) | `rotate_every_days`, resets on password change | `custom_data` |
| Protected entry (0x15) | `locked`: no edit or delete until unlocked by someone with manage rights | `custom_data` |
| Password history (0x0f) | history | `History` |
| Email (0x14) | `login.email` | custom string `Email` [Strongbox convention, not checked] |
| Run command, double-click actions, keyboard shortcut | `custom_data` `pwsafe.*`; never executed by web or mobile | `custom_data` |

References need care across vaults: a reference whose target the reader cannot decrypt shows "unavailable", and sharing an item that references another warns that the target is not shared.

---

## 5. The per-item design (the later path; see "Direction" at the top for what comes first)

### 5.1 Principles

- **Reuse, don't fork.** Vault keys are Drive collection epochs with new purposes; recipients are identity-pinned; envelopes are Kutup envelopes. New crypto formats get new magic bytes and purposes; no existing purpose changes meaning.
- **One Rust core.** Item schema, sealing, merge, KDBX, TOTP, SSH key parsing, passkey signing, URL matching and import parsers live in `kutup-crypto` (or a new `kutup-pass-core` crate beside it), compiled to WASM for the web and extension and exposed via UniFFI (`kutup-client-ffi`) to native apps, and linked into the `kutup` CLI.
- **The server is a dumb, conditional record store** with ACLs, quotas, jobs and a change feed. It never sees names, URLs, usernames or secrets.
- **Offline is the normal case**, not a mode.

### 5.1a Storage formats (decided 2026-10-11 for the per-item design)

*Superseded as the first direction by "KDBX in Kutup Drive" (top of this document); this section applies to the per-item path if it is built later.*

The question was whether Kutup Pass should store vaults as KDBX files, as an encrypted SQLite database, or in its own format.

**The unit of storage and sync is one sealed record per item**, in Kutup's own format (§5.2): each item sealed under its own item key, carrying its revision. The record is identical everywhere; only the container around it differs:

| Where | Container |
|---|---|
| Server | Postgres rows, one sealed item each (the server cannot read them) |
| Website | IndexedDB, as encrypted records ([`16-browser-storage-architecture.md`](16-browser-storage-architecture.md); no SQLite in the browser) |
| `kutup` CLI and native apps | SQLite with SQLCipher, holding the same sealed records (doc 16's choice for native clients; Kutup's Chat engine already uses SQLite) |
| Backup and moving to other apps | A KDBX 4.1 file, lossless (§4), or the encrypted Kutup archive (§5.13) |

**Why not KDBX as the storage or sync format.** KDBX is one file holding the whole vault. Syncing it means every device rewrites the whole file and merges copies afterwards, and every product studied that does this loses edits somewhere: whole-entry last-writer-wins on device clocks (KeePassXC `KXC/core/Merger.cpp:439-492`, Strongbox `SBX/model/Sync/DatabaseMerger.m:304-333`), unconditional overwrites (KeePassDX; Strongbox's Dropbox push `SBX/StrongBox/DropboxV2StorageProvider.m:263`), or no merge at all (KeePassium, `keepassium/KeePassium/database/DatabaseSaving.swift:109-135`). A file also cannot share one item with one person without handing over the whole file and its password (KeeShare, §2.1). KDBX's value is that every KeePass app reads it, so it is the way in and out: import from KeePassXC, export a full backup, leave Kutup at any time.

**Why not encrypted SQLite as the sync format.** A SQLite file is still one file per vault, with the same whole-file sync problem, and browsers cannot use it under Kutup's storage decision. As a **local** store it is the right tool on native platforms: queries, an index for search and autofill, transactions for the outbox. SQLCipher additionally hides the local index and counts on a stolen device; the records inside are sealed regardless.

**Why per-item records make offline reliable.** An edit made offline touches one small record, not the vault; it is sent later as "based on revision N" (a conditional write, §5.5); if someone else changed the same item meanwhile, only that item is merged, field by field, with the losing value kept in history. Bitwarden and Proton Pass already store per-item records; neither added offline writes on top. Kutup Pass would.

### 5.2 Key hierarchy

```
account master key (random, 32 B)                                  [exists, docs/architecture.md]
 │  wrapped by Argon2id(password) and by the 24-word recovery phrase
 │
 ├─ Pass store key (per account, per device store)                 [doc 16 pattern]
 │     encrypts the local replica's index records
 │
 └─ vault key, epoch e  (random 32 B)                              [collection_epoch / collection_keyring pattern]
     │  statement e signed by the owner's Ed25519 authority, hash-linked to e−1,
     │  committing to the key; key(e−1) sealed under key(e)
     │  delivered: own vaults → under the master key;
     │             members  → HPKE named-share envelope, sender-signed, recipient pinned
     │
     ├─ vault metadata record   AEAD(key(e), CBOR{name, description, icon, colour, policies, kdbx bag})
     ├─ folder records          AEAD(key(e), CBOR{name, parent, order, kdbx bag})
     └─ item key, generation g  (random 32 B)                      [file_keyring pattern]
          │  wrapped: AEAD(key(e), item_key, AD = item_id ‖ vault_id ‖ e ‖ g)
          │  item_key(g−1) sealed under item_key(g)
          ├─ item blob     AEAD(item_key, CBOR ItemV1, AD = item_id ‖ revision ‖ schema ‖ g)
          ├─ history blobs one per kept revision, same key generation chain
          ├─ attachment keys → encrypted chunked blobs (Drive storage path)
          └─ link keys     secure links: item_key under link key; link key under the owner's master key
```

Details:

- **AEAD**: XChaCha20-Poly1305, as everywhere else in Kutup (`crates/kutup-crypto/src/local_state.rs` uses the "project-wide XChaCha20-Poly1305 palette").
- **Whole-item blob**: everything secret and everything identifying (name, URLs, usernames, tags, type) is inside one blob. This follows Bitwarden's own conclusion and Proton's practice, and avoids per-field swapping.
- **Binding**: the blob binds item id, revision, schema version and key generation, so a server cannot move content between items or relabel an old revision as new. The wrapped item key binds vault id and epoch, so **moving an item between vaults re-wraps one key** (Proton's `move-item.ts`), without re-encrypting the blob. Clients remember the highest revision seen per item to detect rollback, as identity pins do for their list (`identity_pins.rs`).
- **Revision in the AD** requires the client to know the revision before writing: the write is conditional on `base_revision` and the new revision is `base_revision + 1`; on a 409 the client merges and re-seals.
- **Padding**: pad blobs to size buckets so lengths say little (the idea behind KeePassXC's random slug, `KXC/core/Database.cpp:320-322`).
- **Item size cap**: generous but finite (for example 256 KiB for the blob; Proton caps at ~40 KB), with files as attachments.
- **Author signature (optional, see §7)**: each write carries the author's Ed25519 signature over (item id, revision, blob hash), so clients can show a verifiable "last changed by" and a server cannot forge edits under someone's name. It does not stop another key holder from writing ciphertext; roles remain server-enforced.
- **No per-vault Argon2.** Vault unlock follows from the already unlocked master key, which avoids the AutoFill memory trap entirely on the vault path.

### 5.3 What the server stores

Names are illustrative, not a schema.

| Table | Columns (plaintext unless noted) |
|---|---|
| `pass_vaults` | id, owner account, created/deleted, current epoch, `rotation_pending`, kind (personal / shared) |
| `pass_vault_epochs` | vault id, epoch, signed statement, previous key sealed under this epoch |
| `pass_vault_members` | vault id, member (local account or federated address), role, `expires_at`, `can_autofill`, hidden, status (invited / active / removed), envelope + its epoch, granted by, grant signature |
| `pass_items` | id, vault id, revision, key generation, wrapped item key, sealed blob, padded size, created/updated/trashed timestamps, author account, author signature |
| `pass_item_key_generations` | item id, generation, previous key sealed under this generation |
| `pass_item_revisions` | item id, revision, sealed blob, key generation, author, timestamp (history; quota-charged) |
| `pass_item_shares` | item id, recipient, role, `expires_at`, envelope, status |
| `pass_attachments` | id, item id, storage object, size, wrapped attachment key |
| `pass_links` | id, item id, revision, item key under link key, link key for owner, `expires_at`, `max_reads`, reads |
| `pass_user_records` | account, kind (favourites, per-user folder placement, settings, autofill index, monitor cache), sealed blob, revision |
| `pass_events` | account cursor feed: vault, epoch, membership, item, share, link changes |

What the server learns: how many items each vault has, their padded sizes, when they change and who changed them, who shares with whom and in which role. It does not learn item types, names, URLs or secrets.

### 5.4 API sketch

```
GET    /api/pass/sync?since=<cursor>              → events, new cursor (or 410 "resync")
GET    /api/pass/items?ids=…                       → records
PUT    /api/pass/items/{id}  {base_revision, blob, wrapped_key, key_gen, sig, op_id}
                                                  → 200 {revision} | 409 {current record}
POST   /api/pass/items/{id}/move  {to_vault, wrapped_key, base_revision}
POST   /api/pass/items/{id}/trash | /restore | DELETE (purge)
POST   /api/pass/vaults           {epoch-1 statement, own envelope, metadata}
POST   /api/pass/vaults/{id}/epochs {statement e+1, prev-key envelope, member envelopes[]}
                                                  (conditional on current epoch)
POST   /api/pass/vaults/{id}/members  {recipient, role, expires_at, envelope}
PATCH  /api/pass/vaults/{id}/members/{m}  {role, expires_at}
DELETE /api/pass/vaults/{id}/members/{m}           → sets rotation_pending
POST   /api/pass/items/{id}/shares  …  /  DELETE …
POST   /api/pass/links  {item, revision, wrapped keys, expires_at, max_reads}
GET    /api/pass/public/links/{token}              → item key under link key + blob (public)
POST   /api/pass/attachments  (tus, like Drive)    → charged to the storage pool
```

- `op_id` makes outbox replays idempotent (an op that already landed returns its result).
- Federated members receive envelopes through the existing federation channel, the way Drive named shares travel today (`named_share.rs`); the remote server stores their membership like a local one.
- Push: a WebSocket notification "pass changed, cursor N" (Kutup's server already has a WebSocket hub for other apps), then the client pulls.

### 5.5 Sync and conflicts

1. **Full encrypted replica.** Each client keeps every record it can read: vault epochs and envelopes, folders, items, its own per-user records.
2. **Change feed.** `since=<cursor>` returns changes in server order. Key-epoch and membership events come before the item events that depend on them (the order Proton's iOS client enforces, `PPI/…/EventSynchronizer.swift:28-45`). A cursor older than the server's tombstone retention returns "resync": the client re-lists ids and revisions and fetches the difference.
3. **Durable outbox.** Every local mutation is written first to an encrypted outbox record `{op_id, item_id, base_revision, base blob ref, new blob, created_at}` and applied to the local replica optimistically. It survives reloads and crashes and is replayed in order. Nothing is silently dropped (KeePassium's journal, done as the main path instead of a retrofit, `KPM-Lib/db/transactions/PendingDatabaseTransaction.swift:38-75`).
4. **Conditional writes.** The server accepts a write only if `base_revision == current`. Bitwarden and Proton do this already; Kutup adds the merge instead of "redo your edit".
5. **Three-way merge on 409**, on the decrypted item (base = the version the edit started from, ours, theirs):
   - fields changed on one side apply;
   - lists merge by stable id (URLs, custom fields, passkeys, attachments, tags as a set);
   - a field changed on both sides to different values: the merging device's value is written (it lands last in server order), **the other value goes into history**, and the item is marked "merged, review" in the UI; passwords get a prominent notice, because both may be real (one may have been changed on the website);
   - HOTP counter: max of both, then continue;
   - type changed on one side and edited on the other: keep both (a copy, like pwsafe's `-merged-<time>`, `PWS/src/core/CoreOtherDB.cpp:711-720`);
   - edit vs trash: **edit wins**, the item is restored and the user told (Strongbox, `SBX/model/Sync/DatabaseMerger.m:474-526`). No device clocks decide anything.
6. **Tombstones and trash.** Delete moves to trash with retention (KeePass recycle bin semantics); purge leaves a tombstone in the feed until the retention window passes.
7. **History.** Every accepted write keeps the previous revision in `pass_item_revisions` up to the vault policy (default 10 / 6 MiB, like KeePassXC), counted in the quota. KDBX export writes them as `History`.
8. **Manual review.** A conflict view with Compare, keep mine, keep theirs, keep both, and **later** (Strongbox's wizard, `SBX/model/Sync/SyncAndMergeSequenceManager.m:582-637`).
9. **Bulk operations** (import, merge a KDBX into a vault) run as one undo unit with a dry-run preview (pwsafe's `MultiCommands`, KeePassXC's merge dry run `KXC/gui/MergeDialog.cpp:159, 185`).

### 5.6 Offline

**Web (pass.<domain>).**
- Store: encrypted records in IndexedDB under a per-account store key wrapped by the master key, exactly the decision in [`16-browser-storage-architecture.md`](16-browser-storage-architecture.md). Pass is a natural next store after Chat.
- **Offline unlock is new work.** Today a web session restores its keys with a per-session key only the server holds (`WebSession` in `crates/kutup-crypto/src/local_state.rs`), so a reload without network cannot unlock. Two options:
  1. Cache the account-protection salt, parameters and the master-key envelope locally; offline unlock reruns Argon2id(password) as the login does. No new crypto format. Cost: a stolen browser profile allows offline password guessing at 64 MiB per guess, the same exposure as a KDBX file, and the same as the envelope already held by the server.
  2. Proton's model: a separate offline key from Argon2 of the password, wrapping the store key, set up only after an online check (`PPW/lib/cache/crypto.ts:61-105`). Option 1 reuses more and is recommended; either should be opt-in per device ("keep this browser usable offline").
- WebAuthn PRF unlock (a passkey for Kutup itself) as a later convenience [GK: Bitwarden uses PRF with its `SecretProtectedKeyEnvelope`].
- A service worker serves the app shell offline.

**CLI (`kutup`).** An encrypted replica on disk (the CLI already keeps an encrypted session cache, `CliSession` in `local_state.rs`); same outbox; needed for the SSH agent (§5.8).

**Native apps (later).**
- Local store: SQLite with SQLCipher, as doc 16 states for native clients, holding the same encrypted records.
- A random **device key** wraps the account key material locally and is itself wrapped three ways: by the password (offline unlock), by a Secure Enclave / Android Keystore key that requires `biometryCurrentSet` / user authentication and is invalidated on enrolment change, and optionally by a PIN (Argon2id with low memory + hardware binding + an attempt counter; Bitwarden's split of PIN envelopes kept on disk vs in memory, `BSDK/bitwarden-core/src/key_management/pin_lock_system.rs:22-33`, should be shown honestly).
- **Never store the password for biometric unlock** (KeePassDX, K2A and Strongbox do) and never enforce biometrics only in app code (`SBX/model/SecretStore.m:420-433`).
- **AutoFill extensions never run Argon2.** Kutup's Argon2id is 64 MiB (`kdf.rs:26`), and iOS extensions run near 120 MB (`KPM-Lib/util/MemoryMonitor.swift:12`). The extension unwraps the device key with Face ID, reads a compact encrypted autofill index (domain / rp_id → item id), and decrypts only the matched item.

### 5.7 Sharing and shared accounts

**Units.** Two, as in Proton Pass:
- **Vault share** for families and teams: members get the vault key.
- **Item share** for "send my partner the Wi-Fi password": the recipient gets that item's key only and sees it under "Shared with me". Item shares survive moves because the item key does not change on a move.

**Roles** (server-enforced for writes; reading follows key possession):

| Role | Can |
|---|---|
| Viewer | read, copy, autofill |
| Editor | + create, edit, trash items |
| Manager | + invite, remove, change roles below manager, rotate keys, create links |
| Owner | + delete the vault, transfer ownership (one per vault) |

Per membership: `expires_at` (Proton has it), `can_autofill`, hidden. Do **not** offer Bitwarden's "can view except passwords": it is UI-only (`BSDK/bitwarden-vault/src/cipher/cipher.rs:347`); if it is ever wanted, it must be labelled as a display preference, not protection.

**Inviting a Kutup user (local or federated).**
1. Resolve the recipient's identity through the Drive key binding and identity pins (`drive_key_binding.rs`, `identity_pins.rs`). First seen → gray shield; verified by safety number → green; changed → red warning (warn-not-block, as in [`../plans/drive-identity-pins.md`](../plans/drive-identity-pins.md)).
2. Seal the current vault key (the epoch chain lets the recipient walk back) in an HPKE named-share envelope bound to vault id, epoch, sender and recipient, signed by the sender (`named_share.rs`). Federated recipients get the same envelope over federation.
3. The recipient sees a preview, accepts, verifies the sender against its pins, and (proposal) **re-wraps the vault key under its own master key**, as Proton's accept step does, so daily unlock does not depend on the sender's keys.
4. The server marks the membership active.

**Inviting someone without an account.** Proton's deferred exchange (`PPW/lib/crypto/pass-crypto.ts:554-593`): the inviter signs a binding of (address, vault id, epoch commitment); when that person registers, on this or another Kutup server, the server tells a manager, whose client checks the binding and seals the envelope to the new identity. The server never holds the key. Until then, a **secure link** covers urgent cases.

**Removal, expiry and rotation.**
1. The server drops the membership immediately (ACL), and sets `rotation_pending` on the vault.
2. The next manager client online creates epoch e+1: a new key, a signed statement chained to e, key(e) sealed under key(e+1), and envelopes for the remaining members. This is the Drive revocation flow ([`../plans/drive-share-revocation.md`](../plans/drive-share-revocation.md)).
3. **Lazy re-wrap.** New and edited items wrap their item keys under e+1; untouched items stay under older epochs and remain readable through the walk-back. An optional "re-key now" also rotates every item key (new generation) and re-seals blobs, for high-assurance vaults.
4. While `rotation_pending` is set, clients refuse to wrap new item keys under the stale epoch (Proton's `NOT_LATEST_KEYS` idea).
5. **Item share revoked**: a new item key generation, re-seal the blob, wrap it under the vault key and for the remaining item recipients (the `file_keyring.rs` generation chain). Proton skips this; it is cheap.
6. **"Exposed to a former member, change these."** After any removal or expiry, list every item the person could have read and offer to change the real passwords (Passbolt's expiry-on-access-loss). Kutup does not log plaintext reads, so the default is "all items in the vault at the time"; tracking only items opened would need clients to report views, a privacy trade-off left to §7.

**Shared accounts.** A login item shared with several people, all editors. Password, TOTP and passkeys travel with the item, so everyone can sign in; the UI warns when sharing an item that holds a passkey or SSH key. Each edit shows "changed by X" (signed if author signatures are adopted). Password changes by one person reach the others through the change feed; conflicting changes go through the merge with the losing password in history, so nobody is locked out by a silent overwrite.

**Secure links.** Proton's design on Drive's link pattern: a random link key in the URL fragment (as Kutup public links already do), the item key of the snapshot revision wrapped under it, the link key sealed for the owner so links can be listed and revoked (`DriveEnvelopePurpose::PublicLinkKey` in `crates/kutup-crypto/src/drive_envelope.rs` is the same idea), server `expires_at` and `max_reads`, served from `pass.<domain>/l/…` with a minimal viewer. Admin toggle to disable links.

**Emergency access (optional, later).** Bitwarden's grantee holds the wrapped key from the moment of confirmation and the server gates release (`BWS/Core/Auth/Entities/EmergencyAccess.cs`). If Kutup adds it, make the trust explicit: the server decides timing; the grantor can cancel during the wait; a notification goes to every grantor device. Many users are better served by sharing a vault with a trusted person or printing the recovery kit.

**Groups.** Not in v1. A vault with N members costs N small envelopes per rotation, fine into the hundreds. Org-scale groups would need a group identity whose key is wrapped to members (Proton's group shares); Kutup Chat is moving away from MLS to pairwise structures, so nothing here should build on MLS.

### 5.8 SSH keys

*For the chosen KDBX direction, the SSH agent is decided in "SSH agent in the `kutup` CLI" at the top; the notes below are the per-item path's version and agree with it.*

- **Item type** `ssh_key` (§4.2). The private key is stored as unencrypted OpenSSH text **inside the sealed blob** (Bitwarden's choice); the optional original passphrase is kept so export can re-encrypt the key file.
- **Crypto**: the RustCrypto `ssh-key` crate in the core (Bitwarden uses it in `BSDK/bitwarden-ssh`): generate Ed25519 (default), RSA-3072/4096, ECDSA; import OpenSSH (bcrypt-encrypted), PKCS#8 (encrypted or not), PKCS#1 PEM; compute fingerprints. Same code in WASM, UniFFI and the CLI.
- **Web**: generate, import, view, copy the public key, download the private key. No agent.
- **Agent in the `kutup` CLI** (`kutup pass ssh-agent`):
  - socket `$XDG_RUNTIME_DIR/kutup/ssh-agent.sock`, mode 0600; a named pipe with a configurable name on Windows so the system agent can stay; systemd user unit / launchd plist;
  - keys decrypted from the local replica into an in-memory store, zeroized and dropped on lock or idle timeout;
  - **approval per signature** by default, showing the requesting process, the destination host from `session-bind@openssh.com`, forwarding, and the SSHSIG namespace so `git commit -S` asks separately (`BWN/ssh_agent/src/server/session_bind.rs`, `protocol.rs:31-71`); policies always / remember until lock per host / never (keys `local:<hostfp>`, `forwarded:<hostfp>`, as Bitwarden);
  - headless approval by `SSH_ASKPASS`-style helper, a desktop notification, or `kutup pass approve` on a TTY;
  - **public keys listed while locked**, a sign request triggers unlock (Strongbox);
  - per-item `allowed_hosts`.
- **"Push to system agent" mode**: `kutup pass ssh-add <item> --lifetime 1h --confirm`, KeePassXC's constrained add (`KXC/sshagent/SSHAgent.cpp:270-304`), for people who keep their own agent.
- **KDBX**: export as key attachment + `KeeAgent.settings` with AllowUseOfSshKey / AddAtDatabaseOpen / RemoveAtDatabaseClose / confirm / lifetime mapped from the agent policy, passphrase in the entry password; import reverses it.
- **Native**: a future desktop app embeds the same agent with a GUI prompt; phones view, copy and share keys [GK: no OS-level SSH agent API on iOS or Android].

### 5.9 Passkeys

- **Storage now**: `login.passkeys[]` with explicit fields: credential id, rp id, rp name, user handle, user name, display name, COSE algorithm, PKCS#8 private key, counter (kept at 0), discoverable, created, BE/BS flags, optional PRF seed. These map 1:1 to `KPEX_PASSKEY_*`, Bitwarden's `Fido2Credential` and CXF. Do not copy Proton's opaque blob.
- **Using them** needs an authenticator in the extension (WebAuthn interception, as `BWC/apps/browser/src/autofill/fido2/content/fido2-page-script.ts` and `PPX/app/content/webauthn.ts` do) and in the native app (Android Credential Manager, iOS `ASCredentialProviderViewController`). Implement the authenticator once in Rust (`passkey-rs` [GK licence]) in the core.
- A web page cannot act as an authenticator for other sites; the web app manages passkeys, it does not use them.
- Sharing a login shares its passkey, intentionally, with a warning.

### 5.10 TOTP

- Canonical storage: an `otpauth://` URI in `login.totp`; extra TOTP custom fields allowed (Proton). HOTP with a counter.
- Generation in the core: RFC 6238/4226, SHA-1/256/512, 6–10 digits, any period, Steam encoder (`KXC/core/Totp.cpp:34, 96-110`). Always on the client.
- KDBX: read all four KeePass forms plus `HmacOtp-*`; write `otp` and `TimeOtp-*`.
- Import QR codes and `otpauth-migration://` batches [GK: the Google Authenticator export format] later.

### 5.11 Aliases tied to Kutup Mail

Mail aliases are in flight (`feat/mail-aliases`, A0–A3 in [`../plans/mail-parity.md`](../plans/mail-parity.md)), not shipped. When they exist:
- An `alias` item stores the Mail alias id and a note; the address, forwarding and enable/disable stay in Mail's server-side tables (they must, for routing; Proton keeps `AliasEmail` server-side too).
- "New login with a new alias" is one action, as in Proton (`PPW/lib/items/item.requests.ts:114-146`).
- In shared vaults, mail to an alias still goes to its creator's mailbox; the UI says so.
- Deleting the item asks whether to disable or delete the alias in Mail.

### 5.12 Security monitor

- Weak (zxcvbn-style score), reused (across all vaults the user can read), similar (Levenshtein, Strongbox), too short, expired / expiring (`expires_at`, `rotate_every_days`), missing 2FA where the site supports it (needs a list of 2FA-capable domains [GK: e.g. 2fa.directory], shipped as data), passkey available, policy violations, items exposed to former members. All computed on the client; results cached in a per-user encrypted record. Items with `exclude_from_monitor` are skipped.
- **Breached passwords by k-anonymity**: SHA-1 prefix range queries with padding (Strongbox uses 5 hex characters and `Add-Padding`, `SBX/model/DatabaseAuditor.m:963-969, 1069-1077`; Proton 6, with gzipped buckets and ETags). Proxy through the Kutup server so the third party does not see user IPs. **Self-hosting privacy note**: the Kutup admin then sees which prefixes each account asks for (little, but not nothing); offer a server-side mirror of the bucket files as an option and make the check opt-in per account.
- **No email breach lookups that send addresses in clear to a vendor** (Strongbox `DatabaseAuditor.m:971-985`).

### 5.13 Backup, export and import

| Format | Direction | Purpose |
|---|---|---|
| **KDBX 4.1** (Argon2id, ChaCha20 or AES-256; optional key file) | import + export | the escape hatch and the KeePassXC parity proof (§4) |
| **Kutup archive** (`.kutuppass`: versioned header, Argon2id + XChaCha20-Poly1305 under an export passphrase, items + attachments + history) | import + export | portable backup, restorable into any account on any Kutup server; not tied to the master key, so a key change does not break it (unlike Bitwarden's account-restricted export) |
| JSON / ZIP (plaintext) | export | behind a warning |
| CSV | import + export | lossy; warn which fields are lost |
| CXF | later | FIDO Credential Exchange, OS-level moves [GK: iOS 26] |
| psafe3 | import later | Password Safe users |

- **Scheduled encrypted export to Drive** (opt-in), charged to the same pool. Server-side revision history is not a backup of the account itself.
- **Importer checklist** (structured warnings like Strongbox's `ImportMessage`): KDBX 3.1/4.x and KeePass XML; Bitwarden JSON (plain, encrypted) and CSV; Proton Pass ZIP/JSON/CSV; 1Password 1PUX; Chrome, Edge, Brave, Firefox, Safari / Apple Passwords CSV; LastPass CSV; Dashlane; Enpass JSON; Keeper JSON; NordPass, RoboForm CSV; psafe3 / pwsafe XML; generic CSV. Proton's list (`PPW/lib/import/types.ts:7-26`) and Bitwarden's 80 importers are the reference.
- Importing into a non-empty vault de-duplicates by KDBX UUID, else by title + username + URL host (pwsafe's GTU match, used only as a heuristic), with a dry-run preview and one undo unit.
- Export policy for shared vaults: owners can disable export by others (Proton `ExportMode`, Bitwarden export policies); this is a UI rule, since any member can read the data.

### 5.14 Browser extension and native app implications

- **Extension (later)**: MV3 for Chromium and Firefox; the same WASM core; its own encrypted IndexedDB replica; signs in by a session fork from the account app (Kutup already forks sessions to child apps, `SessionFork` in `local_state.rs`). Anti-phishing defaults from Proton: registrable domain via the public suffix list, exact host on request, regex behind a warning, no fill into cross-origin iframes (`PPX/lib/utils/frames.spec.ts:221-239`), Android app binding by signing-cert hash. Native messaging to the CLI agent for SSH approvals.
- **Native Kutup Pass** (its own repository, iOS + Android, per [`../mobile-build.md`](../mobile-build.md)): Swift/Kotlin UI over the UniFFI core; Credential Manager + Autofill service on Android (with a privileged-browser allowlist and Digital Asset Links); AutoFill extension with QuickType / credential identities on iOS, written by the main app (never secrets); the extension reads the app-group store and the shared keychain group. Shared sign-in with the other Kutup apps is planned in mobile-build.md and would apply here.
- **Design now for later**: the autofill index record, the per-user records, the device-key wrapping and the outbox are in the format from day one, so neither the extension nor the native app needs a migration.

### 5.15 Quota

Items, history revisions, attachments and links count against the account's single storage pool (`users.storage_quota_bytes`, `docs/architecture.md` "one storage pool"), with a "Pass" row on the Account app's storage page. Items are small; history and attachments are what count. Shared vaults charge the owner [proposal; see §7].

---

## 6. Phased roadmap (suggestion)

| Phase | Contents | Unlocks |
|---|---|---|
*These phases are for the per-item path. The direction chosen first is the KDBX one, with phases K0–K4 near the top of this document.*

Ordered by the priorities above: offline first and proven before any UI relies on it; the website is the product being built; sharing last.

| Phase | Contents | Unlocks |
|---|---|---|
| **P0 offline core** | In the shared Rust core (WASM + UniFFI + CLI): item schema (CBOR, versioned, test vectors); sealing and key formats, **with vault epochs and item-key generations in the format from day one** (so sharing needs no migration later); the offline engine — local replica store interface, durable outbox with idempotent `op_id`s, revision-conditional sync client, change-feed cursor and resync, field-level three-way merge with losing values kept in history, tombstones and trash; offline unlock and the device-key wrapping format; KDBX 4.1 codec round-tripping the KeePassXC corpus; TOTP; URL matching. Server: the record store, conditional writes, change feed. | The behaviour every client will share, before any UI exists |
| **P0 proof** | An **offline test harness**: several simulated clients (WASM and native builds of the same core) edit the same vault while disconnected, reconnect in random orders, crash mid-outbox and replay; property tests that no edit is lost and every client converges; the merge test vectors shared across WASM and UniFFI. The `kutup pass` CLI is the **first real offline client**: a full encrypted replica on disk, working with no network, run against a live server in CI. | Confidence that offline is stable before the website or any app depends on it — the native app later reuses a proven engine instead of inventing one |
| **P1 website** | `pass.<domain>`: personal vaults, folders, all item types, attachments, history, trash, generator with policies; IndexedDB replica and outbox through the P0 engine; installable (service worker app shell); opt-in offline unlock per browser; conflict review UI; KDBX import/export, Kutup archive, Bitwarden / Proton / CSV importers; security monitor (weak, reused, 2FA, k-anonymity breaches) | The product: a password manager on the web that keeps working when the connection drops (best-effort offline on the web, §5.6) |
| **P2 SSH and passkey storage** | SSH key type, generation and import; CLI agent with approval, session-bind, git namespace, locked listing; push-to-system-agent; KeeAgent round-trip; passkey fields and import/export (KDBX, Bitwarden, CXF later) | Developers use Kutup Pass daily; passkeys migrate in without loss |
| **P3 client apps** | Browser extension (autofill, save prompts, TOTP fill, WebAuthn authenticator, native messaging to the CLI) and the native Kutup Pass app in its own repository (iOS AutoFill extension, Android Autofill + Credential Manager, SQLCipher store, biometric device key) — **both on the P0 offline engine**, so offline is stable on arrival | Offline on phones and autofill everywhere; timing follows the native-apps decision in mobile-build.md |
| **P4 sharing** | Shared vaults with roles and expiry; item shares; identity-pinned invites, local and federated; rotation on removal; "exposed to former member" report; deferred invites; secure links | Families, teams and shared accounts — no data migration, because the key structure was in place from P0 |
| Later | Emergency access, aliases with Mail, CXF, groups, travel mode / duress, desktop app | |

Aliases depend on Mail aliases landing; they can join P1 or later.

---

## 7. Risks and open questions

**Decisions for the product owner.**
1. **Vault shares only, or item shares too, when sharing comes (P4)?** Item shares need the item-key generation chain (already in the P0 format) and a "Shared with me" view; recommended, but they can follow vault shares. Not urgent: sharing is last by priority.
2. **Re-wrap on accept?** Proton re-wraps the vault key under the recipient's own key on accept. Does Drive do the same for folder shares? Pass should match Drive unless there is a reason not to.
3. **Offline unlock on the web** (needed in P1; the native device-key format is fixed in P0): cache the master-key envelope (option 1, simpler, offline guessing at 64 MiB per guess if the profile is stolen) or a separate Proton-style offline key (option 2)? Per-device opt-in in both cases?
4. **Author signatures on every item write?** They give verifiable "changed by" and stop server forgery under a member's name, at the cost of one signature per write and a key-lookup per verify.
5. **"Exposed" report scope**: all items in the vault at removal time (default, no tracking), or only items the person opened (needs view events reported to the server)?
6. **Who pays quota for a shared vault**: the owner, or each writer for what they add?
7. **Item size cap** (proposed 256 KiB blob) and history defaults (10 / 6 MiB).
8. **Emergency access**: build it, or rely on vault sharing and the printable recovery kit?
9. **Breach checks**: proxy through the Kutup server, server-side mirror, or off by default?
10. **Auto-type and run-command fields**: store-only forever, or a desktop app later that uses them?
11. **Licence**: is Kutup staying AGPL-3.0-only? It decides whether GPL code (KeePassXC, Bitwarden SDK GPL option) may ever be copied.

**Technical risks.**
- **KDBX codec scope.** Reading every variant (KDBX 3.1, AES-KDF, Twofish, key files, broken files KeePassXC tolerates) is large. Use or fork the `keepass` crate [GK: reads KDBX3/4, KDBX4 writing behind a feature] or write Kutup's own; either way the corpus decides. YubiKey challenge-response files need hardware at import time.
- **Merge correctness.** A field-level merge is easy to get subtly wrong (list identity, renamed fields, attachments). It needs property tests and shared test vectors across WASM and native.
- **Rotation liveness.** If no manager comes online, `rotation_pending` stays set and new items cannot be created under a fresh key. Options: any remaining member with editor rights may rotate, or owners get a reminder.
- **Federated rotation.** Remote members' servers must deliver new envelopes and enforce removal; a misbehaving remote server can keep serving old ciphertext to a removed user (who already had it anyway).
- **Metadata visible to the server**: item counts, sizes (padded), timing, share graph. Acceptable for v1; document it in a threat model like the Drive one.
- **Offline brute force** of a stolen device or browser profile is bounded only by Argon2id; PIN unlock on native must be hardware-bound with an attempt limit.
- **Clipboard and memory hygiene** on the web are weak (no `mlock`, GC copies); keep decrypted items short-lived and clear the clipboard after a timeout where the browser allows.
- **Extension store review and phishing**: autofill rules must be strict from the first release; a lax default is hard to take back.
- **iOS extension memory**: keep the autofill index small and test on the smallest supported device.
- **Scope creep**: the requirements already cover what three products do separately. The phase plan keeps the extension and native app out until the core is proven.

---

## 8. References

**Cloned repositories** (in `kutup-references/`, rows from its `README.md`):

| Repo | URL | Commit |
|---|---|---|
| keepassxc | https://github.com/keepassxreboot/keepassxc.git | `9e0f57a` |
| keepassdx | https://github.com/Kunzisoft/KeePassDX.git | `2db52c5` |
| keepass2android | https://github.com/PhilippC/keepass2android.git | `76d8502` |
| keepassium | https://github.com/keepassium/KeePassium.git | `e651df4` |
| strongbox | https://github.com/strongbox-password-safe/Strongbox.git | `c70fc7b` |
| pwsafe | https://github.com/pwsafe/pwsafe.git | `5302047` |
| bitwarden-clients | https://github.com/bitwarden/clients.git | `df96418` |
| bitwarden-server | https://github.com/bitwarden/server.git | `5e68c1e` |
| bitwarden-sdk-internal | https://github.com/bitwarden/sdk-internal.git | `7d5b101` |
| vaultwarden | https://github.com/dani-garcia/vaultwarden.git | `6489552` |
| WebClients (Proton Pass web, extension, desktop) | https://github.com/ProtonMail/WebClients.git | `4c408125` |
| proton-pass-android | https://github.com/protonpass/android-pass.git | `9565065` |
| proton-pass-ios | https://github.com/protonpass/ios-pass.git | `0b0fc36` |
| passbolt-api | https://github.com/passbolt/passbolt_api.git | `8ff0944` |

Not cloned: Bitwarden's Android and iOS apps, Passbolt's browser extension, Proton's `pass-cli` and `proton-pass-common`. Claims about them are [GK].

**Key code references by topic.**

| Topic | Files |
|---|---|
| KDBX format | `KXC/format/KeePass2.h`, `KXC/format/Kdbx4Writer.cpp`, `KXC/format/Kdbx4Reader.cpp`, `KXC/format/KdbxXmlWriter.cpp`, `KXC/format/KeePass2Writer.cpp:50-107` (version selection) |
| KDBX fields and conventions | `KXC/core/EntryAttributes.cpp`, `KXC/core/Totp.cpp`, `KXC/sshagent/KeeAgentSettings.cpp`, `KXC/browser/BrowserService.cpp`, `KXC/core/CustomData.cpp:23-29` |
| KeePass merge | `KXC/core/Merger.cpp`, `KDX-DB/database/merge/DatabaseKDBXMerger.kt`, `K2A/KeePassLib2Android/PwDatabase.cs:690-860`, `SBX/model/Sync/DatabaseMerger.m` |
| Mobile offline/sync | `K2A/Kp2aBusinessLogic/Io/CachingFileStorage.cs`, `KPM-Lib/db/transactions/`, `KPM-Lib/util/MemoryMonitor.swift`, `SBX/model/Sync/SyncAndMergeSequenceManager.m` |
| Password Safe | `PWS/docs/formatV3.txt`, `PWS/docs/formatV4.txt`, `PWS/src/core/Item.h`, `PWS/src/core/CoreAlias.cpp`, `PWS/src/core/CoreOtherDB.cpp` |
| Bitwarden crypto | `BSDK/bitwarden-crypto/src/keys/kdf.rs`, `.../enc_string/symmetric.rs`, `.../safe/`, `BSDK/bitwarden-core/src/key_management/security_state.rs` |
| Bitwarden items | `BSDK/bitwarden-vault/src/cipher/` (`cipher.rs`, `login.rs`, `README.md`, `ssh_key.rs`), `BSDK/bitwarden-vault/src/totp.rs` |
| Bitwarden sync, sharing | `BWC/libs/common/src/vault/services/cipher.service.ts:804-925`, `BWS/Core/Vault/Services/Implementations/CipherService.cs:963-976`, `BWS/Core/AdminConsole/`, `BSDK/bitwarden-send/src/send.rs` |
| SSH agents | `BWN/ssh_agent/src/`, `PPD/native/napi/src/ssh_agent/mod.rs`, `SBX/macbox/ssh-agent/`, `KXC/sshagent/SSHAgent.cpp` |
| Passkeys | `KXC/browser/BrowserPasskeys.cpp`, `BSDK/bitwarden-fido/`, `KDX-APP/credentialprovider/passkey/`, `PPW/types/protobuf/protos/item-v1.proto:19-33` |
| Proton Pass crypto and sharing | `PPW/lib/crypto/processes/` (vault, item, share, invite, secure-link, access-token), `PPW/lib/crypto/share-manager.ts`, `PPW/types/api/pass.ts:1363-1407` |
| Proton Pass offline/sync | `PPW/lib/cache/crypto.ts`, `PPW/lib/sync/v2/`, `PPA/pass/data/impl/.../ItemEntity.kt`, `PPI/LocalPackages/Client/Sources/Client/EventLoop/EventSynchronizer.swift` |
| Passbolt | `PB/src/Service/Resources/ResourcesShareService.php`, `PB/src/Service/Secrets/SecretsUpdateSecretsService.php`, `PB/plugins/PassboltCe/PasswordExpiry/`, `PB/plugins/PassboltCe/OfflineMode/`, `PB/plugins/PassboltCe/Metadata/` |
| Import/export | `KXC/gui/wizard/ImportWizard.h`, `SBX/model/import/`, `BWC/libs/importer/src/importers/`, `BSDK/bitwarden-exporters/`, `PPW/lib/import/`, `PPW/lib/export/` |

**Kutup documents and code this builds on.**

- [`../architecture.md`](../architecture.md): master key, Argon2id, recovery phrase, one storage pool.
- [`16-browser-storage-architecture.md`](16-browser-storage-architecture.md): encrypted records in IndexedDB.
- [`../plans/drive-share-revocation.md`](../plans/drive-share-revocation.md), [`../plans/drive-identity-pins.md`](../plans/drive-identity-pins.md), [`../plans/drive-file-sharing.md`](../plans/drive-file-sharing.md): epochs, pins, single-object shares.
- [`../mobile-build.md`](../mobile-build.md): one native app per product, native work after the web apps.
- [`../plans/mail-parity.md`](../plans/mail-parity.md): Mail aliases in flight.
- [`17-mail-calendar-contacts.md`](17-mail-calendar-contacts.md): Contacts and the address book, for choosing share recipients.
- `crates/kutup-crypto/src/`: `kdf.rs`, `identity.rs`, `identity_pins.rs`, `drive_key_binding.rs`, `safety_number.rs`, `collection_epoch.rs`, `collection_keyring.rs`, `file_keyring.rs`, `named_share.rs`, `drive_envelope.rs`, `local_state.rs`.
