//! Notes, code files and place lists in `kutup sync` (docs/plans/cli-yjs-sync.md).
//!
//! Drive holds these as an editor's live state: the newest `yjs` version and
//! the collaboration log after it. The CLI edits them as a peer, like a
//! browser tab: it rebuilds the document, applies a local edit as the fewest
//! Yjs operations (diffed against the state it last synced, so edits made
//! elsewhere since merge instead of being undone), sends it as one signed
//! frame, and writes the merged document back to disk.

use kutup_crypto::primitives::{hash, Suite};
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_collab::{ListDoc, TextDoc};
use kutup_crypto::drive_object::{decrypt_file_blob, encrypt_file_blob, DriveFileBlobContextV1};
use kutup_crypto::envelope::{self, kind, CollabFrameContextV1, Frame};

use crate::api::versions::{NewVersion, VersionRow};
use crate::api::{ApiError, Client, File};
use crate::collab_device::{not_authorized, Device, Signer};
use crate::keyring::Keyring;
use crate::session::{Session, Store, YjsBase, YjsWriting};

/// The CLI as a collaboration peer for one sync run: its device, registered
/// (or renewed) on first use, so a run without notes or lists registers
/// nothing.
pub struct Peer<'a> {
    client: &'a Client,
    store: &'a Store,
    sess: &'a Session,
    signer: Option<Signer<'a>>,
    device: Option<Device>,
}

impl<'a> Peer<'a> {
    pub fn new(client: &'a Client, store: &'a Store, sess: &'a Session) -> Self {
        Peer {
            client,
            store,
            sess,
            signer: None,
            device: None,
        }
    }

    fn signer(&mut self) -> Result<&Signer<'a>> {
        if self.signer.is_none() {
            self.signer = Some(Signer::new(self.client, self.store, self.sess)?);
        }
        Ok(self.signer.as_ref().expect("set above"))
    }

    fn device(&mut self) -> Result<&Device> {
        if self.device.is_none() {
            let device = self.signer()?.device()?;
            self.device = Some(device);
        }
        Ok(self.device.as_ref().expect("set above"))
    }

    /// Runs `call` with the device; once more with a new one when the server
    /// no longer takes it (revoked, or of an earlier identity).
    fn with_device<T>(&mut self, mut call: impl FnMut(&Device) -> Result<T>) -> Result<T> {
        match call(self.device()?) {
            Err(e) if not_authorized(&e) => {
                let device = self.signer()?.recover()?;
                self.device = Some(device);
                call(self.device.as_ref().expect("set above"))
            }
            other => other,
        }
    }
}

/// A note's text or a list's places.
enum Doc {
    Text(TextDoc),
    List(ListDoc),
}

impl Doc {
    fn new(list: bool) -> Doc {
        // A fresh Yjs client id per document, as a tab has.
        let client = u64::from(u32::from_le_bytes(kutup_crypto::primitives::random_array()));
        if list {
            Doc::List(ListDoc::new(client))
        } else {
            Doc::Text(TextDoc::new(client))
        }
    }

    fn apply_v1(&self, update: &[u8]) -> Result<()> {
        match self {
            Doc::Text(d) => d.apply_v1(update),
            Doc::List(d) => d.apply_v1(update),
        }
        .map_err(|e| anyhow!("{e}"))
    }

    fn apply_v2(&self, state: &[u8]) -> Result<()> {
        match self {
            Doc::Text(d) => d.apply_v2(state),
            Doc::List(d) => d.apply_v2(state),
        }
        .map_err(|e| anyhow!("{e}"))
    }

    fn state_v2(&self) -> Vec<u8> {
        match self {
            Doc::Text(d) => d.state_v2(),
            Doc::List(d) => d.state_v2(),
        }
    }

    /// The file's bytes on disk: the text, or the list as JSON.
    fn render(&self) -> Vec<u8> {
        match self {
            Doc::Text(d) => d.text().into_bytes(),
            Doc::List(d) => kutup_collab::encode_list_json(&d.places()),
        }
    }

    /// Makes the document what `local` (the file on disk) says; the change
    /// as one Yjs update, or `None`.
    fn edit_to(&self, local: &[u8]) -> Result<Option<Vec<u8>>> {
        match self {
            Doc::Text(d) => {
                let text = std::str::from_utf8(local)
                    .map_err(|_| anyhow!("not UTF-8 text; edit it in the browser"))?;
                Ok(d.set_text(text))
            }
            Doc::List(d) => {
                let places = kutup_collab::parse_list_json(local)
                    .map_err(|_| anyhow!("not a Kutup place list (format kutupmap, version 1)"))?;
                d.set_places(&places).map_err(|e| anyhow!("{e}"))
            }
        }
    }

    /// Whether `local` (the file on disk) is what the document holds: the
    /// same text, or the same places however the JSON is laid out.
    fn holds(&self, local: &[u8]) -> bool {
        match self {
            Doc::Text(d) => d.text().as_bytes() == local,
            Doc::List(d) => kutup_collab::parse_list_json(local).is_ok_and(|places| {
                kutup_collab::encode_list_json(&places)
                    == kutup_collab::encode_list_json(&d.places())
            }),
        }
    }

    /// The first content of a file nobody has opened, made from its file's
    /// bytes as every editor makes it (the same Yjs item wherever it is
    /// made; `kutup-collab` and the web share vectors for it).
    fn seed(list: bool, file_id: &str, content: &[u8]) -> Vec<u8> {
        if list {
            kutup_collab::seed_list_upload(file_id, content)
        } else {
            kutup_collab::seed_text_upload(file_id, content)
        }
    }
}

/// The file's document as Drive has it now.
struct Remote {
    doc: Doc,
    /// Every frame up to here is in `doc`.
    through: i64,
    doc_key_id: u32,
    /// The sequence this run's frames count up from: a random prefix above
    /// every one this device has used (`randomSenderSeqPrefix` on the web),
    /// so two runs at once, or a run after the log was trimmed, never reuse
    /// one.
    sender_next: i64,
    /// Nobody has opened it: no saved state, no frame. `doc` holds the seed
    /// (applied here, sent only in front of an edit).
    seed: Option<Vec<u8>>,
}

/// A file and its keys: its current one, and older generations as frames
/// and versions name them.
struct Keys {
    file: File,
    current: [u8; 32],
}

impl Keys {
    fn at(&self, generation: u32) -> Result<[u8; 32]> {
        crate::file_crypto::key_at(&self.file, &self.current, generation)
    }
}

fn newest_yjs(versions: &[VersionRow]) -> Option<&VersionRow> {
    // Newest first, as the server lists them; a stray whole-file version is
    // never this document's state.
    versions.iter().find(|v| v.kind == "yjs")
}

fn read_remote(
    client: &Client,
    peer: &mut Peer,
    keys: &Keys,
    base: Option<&(Vec<u8>, i64)>,
    list: bool,
) -> Result<Remote> {
    let file = &keys.file;
    let doc = Doc::new(list);
    let mut after = 0;
    if let Some((state, seq)) = base {
        doc.apply_v2(state)?;
        after = *seq;
    }
    let mut page = peer.with_device(|d| client.collab_frames(&file.id, d.id, after))?;
    let mut saved = false;
    // No base, or the log was trimmed past it: start from the newest saved
    // state (merging it in is safe), and read the log after it.
    if base.is_none() || page.floor > after {
        if let Some(version) = newest_yjs(&client.list_versions(&file.id)?) {
            saved = true;
            if version.size_bytes > 0 {
                let blob = client.download_version(&file.id, &version.id)?;
                let context = DriveFileBlobContextV1::new(&file.id, version.key_generation)?;
                let state = decrypt_file_blob(&blob, &keys.at(version.key_generation)?, context)
                    .context("open the saved state")?;
                doc.apply_v2(&state)?;
            }
            if version.seq_at_snapshot > after {
                after = version.seq_at_snapshot;
                page = peer.with_device(|d| client.collab_frames(&file.id, d.id, after))?;
            }
        }
    }
    let mut through = after;
    loop {
        for logged in &page.frames {
            apply_frame(&doc, keys, &logged.bytes()?)?;
            through = through.max(logged.seq);
        }
        if !page.more {
            break;
        }
        page = peer.with_device(|d| client.collab_frames(&file.id, d.id, through))?;
    }
    let never_opened = !saved && page.head_seq == 0 && base.is_none_or(|(_, seq)| *seq == 0);
    let seed = if never_opened {
        let content = current_content(client, keys)?;
        let seed = Doc::seed(list, &file.id, &content);
        doc.apply_v1(&seed)?;
        Some(seed)
    } else {
        None
    };
    Ok(Remote {
        doc,
        through,
        doc_key_id: u32::try_from(page.current_doc_key_id)
            .ok()
            .filter(|id| *id > 0)
            .ok_or_else(|| anyhow!("the server sent no document key id"))?,
        sender_next: sender_prefix(page.my_sender_seq_high),
        seed,
    })
}

/// Applies one frame of the log: document edits only (presence and the
/// like are for live tabs). A frame that does not open under the file's key
/// is skipped, as a tab skips it: the server cannot read frames, so it
/// cannot vouch for their content.
fn apply_frame(doc: &Doc, keys: &Keys, packed: &[u8]) -> Result<()> {
    let Ok(frame) = Frame::unpack(packed) else {
        return Ok(());
    };
    if frame.kind != kind::YJS_UPDATE {
        return Ok(());
    }
    let key = keys.at(frame.key_generation)?;
    let Ok((_, update)) = envelope::open(packed, &key, &keys.file.id, frame.key_generation) else {
        eprintln!("    skipped a frame that does not open under the file's key");
        return Ok(());
    };
    if doc.apply_v1(&update).is_err() {
        eprintln!("    skipped a frame that is not a Yjs update");
    }
    Ok(())
}

/// What a file nobody has opened holds, decrypted, as the editors seed from
/// it: its newest whole-file version, else its upload.
fn current_content(client: &Client, keys: &Keys) -> Result<Vec<u8>> {
    let file = &keys.file;
    let (key, generation) = crate::file_crypto::content_key(file, &keys.current)?;
    let (response, _) = client
        .download_current_stream(&file.id)
        .context("download the file")?;
    let blob = response.bytes().context("download the file")?;
    let context = DriveFileBlobContextV1::new(&file.id, generation)?;
    Ok(decrypt_file_blob(&blob, &key, context)?)
}

/// A sender sequence prefix above `must_exceed`: 31 random bits, shifted
/// past the counter's 32 (as `randomSenderSeqPrefix`).
fn sender_prefix(must_exceed: i64) -> i64 {
    // Bounded: near the top of the range a random prefix above is rare, and
    // then the count simply goes on from the highest.
    for _ in 0..64 {
        let candidate =
            i64::from(u32::from_le_bytes(kutup_crypto::primitives::random_array()) & 0x7FFF_FFFF)
                << 32;
        if candidate > must_exceed {
            return candidate;
        }
    }
    must_exceed.saturating_add(1)
}

/// Sends `update` as one signed frame; its log position. A sequence another
/// run of this device took in the meantime is retried once above it.
fn send(
    client: &Client,
    peer: &mut Peer,
    keys: &Keys,
    remote: &mut Remote,
    update: &[u8],
) -> Result<i64> {
    if update.len() > envelope::MAX_PLAINTEXT_BYTES {
        bail!(
            "this edit is larger than one collaboration frame holds (1 MiB); \
             make it in smaller steps"
        );
    }
    let file = &keys.file;
    let mut attempt = 0;
    loop {
        remote.sender_next += 1;
        let sequence = remote.sender_next;
        let result = peer.with_device(|device| {
            let context = CollabFrameContextV1::new(
                kind::YJS_UPDATE,
                file.key_generation,
                remote.doc_key_id,
                &file.id,
                device.id as u64,
                sequence as u64,
            )?;
            let unsigned = envelope::seal_unsigned(update, &keys.current, context)?;
            let signed = envelope::sign(&Frame::unpack(&unsigned)?, device.seed())?;
            client.post_collab_frame(&file.id, device.id, signed)
        });
        match result {
            Err(e) if attempt == 0 && refused(&e) => {
                attempt += 1;
                // Re-read the document key and this device's sequences, and
                // go on above them under a new prefix.
                let page =
                    peer.with_device(|d| client.collab_frames(&file.id, d.id, remote.through))?;
                remote.sender_next = sender_prefix(page.my_sender_seq_high);
                remote.doc_key_id =
                    u32::try_from(page.current_doc_key_id).unwrap_or(remote.doc_key_id);
            }
            other => return other,
        }
    }
}

fn refused(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|e| e.downcast_ref::<ApiError>())
        .any(|e| e.status == 409 && e.code.as_deref() == Some("frameRefused"))
}

/// Saves the document as a `yjs` version, as the editor's autosave does: the
/// log up to `remote.through` is in it, and the server trims the log there.
fn snapshot(client: &Client, keys: &Keys, remote: &Remote) -> Result<()> {
    let file = &keys.file;
    let context = DriveFileBlobContextV1::new(&file.id, file.key_generation)?;
    let sealed = encrypt_file_blob(&remote.doc.state_v2(), &keys.current, context)?;
    client.create_version(
        &file.id,
        sealed,
        &NewVersion {
            kind: "yjs".into(),
            seq_at_snapshot: remote.through,
            doc_key_id: i64::from(remote.doc_key_id),
            label: String::new(),
            keep_forever: false,
            based_on: None,
        },
    )?;
    Ok(())
}

/// What a sync of one file did.
#[derive(Debug, Default, PartialEq)]
pub struct Synced {
    /// A local edit went up.
    pub sent: bool,
    /// The file on disk was (re)written with edits made elsewhere.
    pub written: bool,
    /// Both sides had the file without a sync between them, and they
    /// differed: Drive's copy was kept under this name, and the local file's
    /// content went up as an edit.
    pub conflict_copy: Option<String>,
    /// The file changed on disk while it was being synced: nothing written;
    /// the next run takes it.
    pub busy: bool,
    /// The file as recorded in sync (taken where it was compared or
    /// written), when it is.
    pub stat: Option<crate::syncengine::LocalFile>,
}

/// One file to sync.
pub struct Target<'a> {
    pub store: &'a Store,
    pub pair: &'a str,
    pub rel: &'a str,
    pub abs: std::path::PathBuf,
    pub file: &'a File,
    pub dir_keys: &'a Keyring,
    /// The folder holding it, and its key epoch (an edit goes under a key
    /// only the folder's current people hold).
    pub collection_id: &'a str,
    pub folder_epoch: u32,
    /// A name for Drive's copy when both sides differ without a base.
    pub conflict_name: &'a dyn Fn() -> Result<String>,
    pub root: &'a Path,
}

/// The base recorded for `target`, when it is for this file.
fn base_of(target: &Target) -> Result<Option<YjsBase>> {
    Ok(target
        .store
        .yjs_base(target.pair, target.rel)?
        .filter(|base| base.file_id == target.file.id))
}

fn base_state(base: &YjsBase) -> Result<(Vec<u8>, i64)> {
    Ok((STANDARD.decode(&base.state)?, base.seq))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hash(Suite::V1, bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Records the base of a note or list the sync just uploaded as a new file:
/// nobody has opened it, so its document is the seed of `uploaded`.
pub fn record_upload(
    store: &Store,
    pair: &str,
    rel: &str,
    file_id: &str,
    uploaded: &[u8],
) -> Result<()> {
    let list = crate::editor_kind::is_place_list(rel);
    let doc = Doc::new(list);
    doc.apply_v1(&Doc::seed(list, file_id, uploaded))?;
    store.put_yjs_base(
        pair,
        rel,
        &YjsBase {
            file_id: file_id.to_owned(),
            state: STANDARD.encode(doc.state_v2()),
            seq: 0,
            pending: Vec::new(),
            writing: None,
        },
    )
}

/// Whether a file that was deleted locally may be deleted on Drive: its
/// document is still what was last synced. An edit made elsewhere since wins
/// over the deletion, as for any other file.
pub fn unchanged_since_base(client: &Client, peer: &mut Peer, target: &Target) -> Result<bool> {
    let Some(base) = base_of(target)? else {
        return Ok(false);
    };
    let base = base_state(&base)?;
    let list = crate::editor_kind::is_place_list(target.rel);
    let keys = Keys {
        file: target.file.clone(),
        current: crate::file_crypto::open_key(target.file, target.dir_keys)?,
    };
    let recorded = Doc::new(list);
    recorded.apply_v2(&base.0)?;
    let remote = read_remote(client, peer, &keys, Some(&base), list)?;
    Ok(remote.doc.render() == recorded.render())
}

/// Test builds only: `KUTUP_TEST_YJS_FAULT=<point>` stops the process at
/// that point (`after-send`, `after-write`), or edits the file there
/// (`touch-after-send`), so the live check can prove a later run makes no
/// edit twice (scripts/verify-yjs-sync.sh).
fn fault(point: &str, file: &Path) {
    if !cfg!(debug_assertions) {
        return;
    }
    let Ok(wanted) = std::env::var("KUTUP_TEST_YJS_FAULT") else {
        return;
    };
    if wanted == point {
        eprintln!("    (test fault: stopped {point})");
        std::process::exit(99);
    }
    if wanted == format!("touch-{point}") {
        use std::io::Write as _;
        if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(file) {
            let _ = f.write_all(b"touched\n");
        }
    }
}

/// Settles a write the last run began: from what the file holds, whether
/// the merged document reached it.
/// `false` when it cannot tell: the file was changed since, so neither state
/// is the one it holds. The base is then dropped, and the file synced as one
/// never synced (Drive's copy kept beside it, the local content an edit over
/// it), rather than diffed against a guess.
fn settle_writing(target: &Target, base: &mut YjsBase) -> Result<bool> {
    let Some(writing) = base.writing.take() else {
        return Ok(true);
    };
    let local = std::fs::read(&target.abs).unwrap_or_default();
    match sha256_hex(&local) {
        hash if hash == writing.after => {
            base.state = writing.state;
            base.seq = writing.seq;
        }
        hash if hash == writing.before => {}
        _ => {
            target.store.delete_yjs_base(target.pair, target.rel)?;
            return Ok(false);
        }
    }
    target.store.put_yjs_base(target.pair, target.rel, base)?;
    Ok(true)
}

/// Syncs one note, code file or place list both ways; records where it is
/// in sync. `local_changed`: the file on disk differs from what was last
/// recorded (or there is no record).
///
/// Crash-safe in order: a local edit is recorded (as the base, with its
/// update bytes pending) before it is sent, and sent again byte for byte
/// until acknowledged; a merged document is recorded as being written before
/// it is, and settled from the file afterwards. No run ever makes the same
/// edit twice as new operations.
pub fn sync_file(
    client: &Client,
    peer: &mut Peer,
    target: &Target,
    local_changed: bool,
) -> Result<Synced> {
    let list = crate::editor_kind::is_place_list(target.rel);
    let mut out = Synced::default();
    let file_key =
        crate::file_crypto::open_key(target.file, target.dir_keys).context("decrypt file key")?;
    let mut base = base_of(target)?;
    if let Some(known) = base.as_mut() {
        if !settle_writing(target, known)? {
            base = None;
        }
    }
    let mut keys = Keys {
        file: target.file.clone(),
        current: file_key,
    };
    let recorded_state = base.as_ref().map(base_state).transpose()?;
    let mut remote = read_remote(client, peer, &keys, recorded_state.as_ref(), list)?;

    // Updates the last run did not see acknowledged: the same bytes again.
    if let Some(base) = base.as_mut().filter(|b| !b.pending.is_empty()) {
        let pending: Vec<Vec<u8>> = base
            .pending
            .iter()
            .map(|u| STANDARD.decode(u))
            .collect::<std::result::Result<_, _>>()?;
        for update in &pending {
            remote.doc.apply_v1(update)?;
            send(client, peer, &keys, &mut remote, update)?;
        }
        base.pending.clear();
        target.store.put_yjs_base(target.pair, target.rel, base)?;
        out.sent = true;
    }

    let before = std::fs::metadata(&target.abs).ok();
    let local = match &before {
        Some(_) => Some(std::fs::read(&target.abs).context("read the local file")?),
        None => None,
    };
    // The local edit, as Yjs operations, and the state the file then holds.
    let edit = match (&local, &recorded_state) {
        (Some(local), Some((state, seq))) if local_changed => {
            // Against the state last synced: what the user changed since.
            let recorded = Doc::new(list);
            recorded.apply_v2(state)?;
            recorded
                .edit_to(local)?
                .map(|update| (update, recorded.state_v2(), *seq))
        }
        (Some(local), None) if !remote.doc.holds(local) => {
            // Never synced, and different: Drive's copy is kept beside it,
            // and the local content goes up as an edit over it.
            let copy = (target.conflict_name)()?;
            write_new(&target.root.join(&copy), &remote.doc.render())?;
            out.conflict_copy = Some(copy);
            let mine = Doc::new(list);
            mine.apply_v2(&remote.doc.state_v2())?;
            mine.edit_to(local)?
                .map(|update| (update, mine.state_v2(), remote.through))
        }
        _ => None,
    };
    if let Some((update, state_with_edit, seq)) = edit {
        // Content goes under a key only the folder's current people hold.
        let (file, current) = crate::cryptohelpers::rekey_file_if_behind(
            client,
            keys.file.clone(),
            keys.current,
            target.dir_keys,
            target.collection_id,
            target.folder_epoch,
        )?;
        keys = Keys { file, current };
        // Nobody has opened it: its first content goes in first. The seed is
        // the same Yjs item wherever it is made (shared vectors pin the
        // bytes), so a copy another editor sent, or sends later, merges into
        // this one: the CLI sends it whoever won the claim, never waits for a
        // claimer that may never send, and never makes the text twice.
        let seeding = remote.seed.take();
        let mut updates: Vec<Vec<u8>> = seeding.iter().cloned().collect();
        updates.push(update);
        // Recorded before it is sent: whatever happens next, the next run
        // sends these bytes, never a new edit of the same change.
        let journal = YjsBase {
            file_id: target.file.id.clone(),
            state: STANDARD.encode(&state_with_edit),
            seq,
            pending: updates.iter().map(|u| STANDARD.encode(u)).collect(),
            writing: None,
        };
        target
            .store
            .put_yjs_base(target.pair, target.rel, &journal)?;
        // The claim tells tabs the first content is there (they then load
        // it rather than seed); its answer changes nothing here.
        if seeding.is_some() {
            if let Err(e) = client.claim_seed(&target.file.id) {
                eprintln!(
                    "    note: claiming the first content of {}: {e:#}",
                    target.rel
                );
            }
        }
        for update in &updates {
            remote.doc.apply_v1(update)?;
            send(client, peer, &keys, &mut remote, update)?;
        }
        fault("after-send", &target.abs);
        base = Some(YjsBase {
            pending: Vec::new(),
            ..journal
        });
        target
            .store
            .put_yjs_base(target.pair, target.rel, base.as_ref().expect("set above"))?;
        out.sent = true;
    }

    let merged = remote.doc.render();
    let merged_base = YjsBase {
        file_id: target.file.id.clone(),
        state: STANDARD.encode(remote.doc.state_v2()),
        seq: remote.through,
        pending: Vec::new(),
        writing: None,
    };
    // Not over an edit made while this ran: the next run takes it (the base
    // is what the file held when read, so its edit is diffed right).
    let unchanged =
        || std::fs::metadata(&target.abs).ok().map(|m| stamp(&m)) == before.as_ref().map(stamp);
    if local.as_deref() != Some(merged.as_slice()) {
        if !unchanged() {
            out.busy = true;
            return Ok(out);
        }
        let writing = YjsBase {
            writing: Some(YjsWriting {
                before: sha256_hex(local.as_deref().unwrap_or_default()),
                after: sha256_hex(&merged),
                state: merged_base.state.clone(),
                seq: merged_base.seq,
            }),
            ..base.clone().unwrap_or_else(|| YjsBase {
                // Nothing here yet: an empty document is what the absent
                // file held.
                state: STANDARD.encode(Doc::new(list).state_v2()),
                seq: 0,
                ..merged_base.clone()
            })
        };
        target
            .store
            .put_yjs_base(target.pair, target.rel, &writing)?;
        // The stat of what this run wrote (taken before the rename): a save
        // after it is a change for the next run.
        let written = write_new(&target.abs, &merged)?;
        fault("after-write", &target.abs);
        target
            .store
            .put_yjs_base(target.pair, target.rel, &merged_base)?;
        out.written = true;
        out.stat = Some(written);
    } else {
        target
            .store
            .put_yjs_base(target.pair, target.rel, &merged_base)?;
        // The stat taken where the file was read and compared.
        match (&before, unchanged()) {
            (Some(meta), true) => out.stat = Some(crate::syncengine::local_file_of(meta)),
            _ => out.busy = true,
        }
    }
    if out.sent {
        // Saved as the editor's autosave saves after an edit, so CLI-only
        // use keeps the log short. A convenience: the edit is in the log.
        if let Err(e) = snapshot(client, &keys, &remote) {
            eprintln!("    could not save a version of {}: {e:#}", target.rel);
        }
    }
    Ok(out)
}

fn stamp(meta: &std::fs::Metadata) -> (u64, Option<std::time::SystemTime>) {
    (meta.len(), meta.modified().ok())
}

/// Writes `bytes` to `dest` through a temporary file beside it (its own
/// name, so two writers never share one), synced to disk with the folder
/// before the run goes on. The written file's stat (a rename keeps it).
fn write_new(dest: &Path, bytes: &[u8]) -> Result<crate::syncengine::LocalFile> {
    use std::io::Write as _;
    let name = dest
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("bad file name"))?;
    let parent = dest.parent().ok_or_else(|| anyhow!("bad file path"))?;
    std::fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(
        ".kutup-tmp-{name}-{:016x}",
        u64::from_le_bytes(kutup_crypto::primitives::random_array())
    ));
    let written = (|| -> std::io::Result<std::fs::Metadata> {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        file.metadata()
    })();
    let meta = match written.and_then(|meta| std::fs::rename(&tmp, dest).map(|()| meta)) {
        Ok(meta) => meta,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e).context("write the file");
        }
    };
    // The rename itself, durable (a folder cannot be opened for this on
    // every platform; there it is the system's to keep).
    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(crate::syncengine::local_file_of(&meta))
}
