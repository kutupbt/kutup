//! Notes, code files and place lists in `kutup sync` (docs/plans/cli-yjs-sync.md).
//!
//! Drive holds these as an editor's live state: the newest `yjs` version and
//! the collaboration log after it. The CLI edits them as a peer, like a
//! browser tab: it rebuilds the document, applies a local edit as the fewest
//! Yjs operations (diffed against the state it last synced, so edits made
//! elsewhere since merge instead of being undone), sends it as one signed
//! frame, and writes the merged document back to disk.

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
use crate::session::{Session, Store, YjsBase};

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
        let client = u64::from(rand::random::<u32>());
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

    /// The first content of a file nobody has opened, made from its upload as
    /// every editor makes it (the same Yjs item wherever it is made).
    fn seed(list: bool, file_id: &str, original: &[u8]) -> Vec<u8> {
        if list {
            // A list whose upload is not one starts empty, as in the editor.
            let places = kutup_collab::parse_list_json(original).unwrap_or_default();
            kutup_collab::seed_list(file_id, &places)
        } else {
            kutup_collab::seed_text(file_id, &String::from_utf8_lossy(original))
        }
    }
}

/// The file's document as Drive has it now.
struct Remote {
    doc: Doc,
    /// Every frame up to here is in `doc`.
    through: i64,
    doc_key_id: u32,
    /// This device's highest sender sequence in the log.
    sender_high: i64,
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
        let original = original_bytes(client, keys)?;
        let seed = Doc::seed(list, &file.id, &original);
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
        sender_high: page.my_sender_seq_high,
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

/// The original upload, decrypted (the content of a file nobody has opened).
fn original_bytes(client: &Client, keys: &Keys) -> Result<Vec<u8>> {
    let file = &keys.file;
    let blob = client
        .download_original(&file.id)
        .context("download the original upload")?;
    let context = DriveFileBlobContextV1::new(&file.id, file.original_key_generation)?;
    Ok(decrypt_file_blob(
        &blob,
        &keys.at(file.original_key_generation)?,
        context,
    )?)
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
        remote.sender_high += 1;
        let sequence = remote.sender_high;
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
                // Re-read where this device's sequence and the document key
                // are now, then try once more.
                let page =
                    peer.with_device(|d| client.collab_frames(&file.id, d.id, remote.through))?;
                remote.sender_high = remote.sender_high.max(page.my_sender_seq_high);
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
    /// The file changed on disk while it was being synced: nothing written or
    /// recorded; the next run takes it.
    pub busy: bool,
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
fn base_of(target: &Target) -> Result<Option<(Vec<u8>, i64)>> {
    Ok(match target.store.yjs_base(target.pair, target.rel)? {
        Some(base) if base.file_id == target.file.id => {
            Some((STANDARD.decode(&base.state)?, base.seq))
        }
        _ => None,
    })
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

/// Syncs one note, code file or place list both ways; records where it is
/// in sync. `local_changed`: the file on disk differs from what was last
/// recorded (or there is no record).
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
    let base = base_of(target)?;
    let mut keys = Keys {
        file: target.file.clone(),
        current: file_key,
    };
    let mut remote = read_remote(client, peer, &keys, base.as_ref(), list)?;

    let before = std::fs::metadata(&target.abs).ok();
    let local = match &before {
        Some(_) => Some(std::fs::read(&target.abs).context("read the local file")?),
        None => None,
    };
    // The local edit, as Yjs operations.
    let edit = match (&local, &base) {
        (Some(local), Some((state, _))) if local_changed => {
            // Against the state last synced: what the user changed since.
            let recorded = Doc::new(list);
            recorded.apply_v2(state)?;
            recorded.edit_to(local)?
        }
        (Some(local), None) if !remote.doc.holds(local) => {
            // Never synced, and different: Drive's copy is kept beside it,
            // and the local content goes up as an edit over it.
            let copy = (target.conflict_name)()?;
            write_new(&target.root.join(&copy), &remote.doc.render())?;
            out.conflict_copy = Some(copy);
            remote.doc.edit_to(local)?
        }
        _ => None,
    };
    if let Some(update) = edit {
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
        if let Some(seed) = remote.seed.take() {
            // The first content goes in first, once (every seeder's is the
            // same item); the claim tells tabs it is there.
            client.claim_seed(&target.file.id)?;
            send(client, peer, &keys, &mut remote, &seed)?;
        }
        remote.doc.apply_v1(&update)?;
        send(client, peer, &keys, &mut remote, &update)?;
        out.sent = true;
    }

    let merged = remote.doc.render();
    if local.as_deref() != Some(merged.as_slice()) {
        // Not over an edit made while this ran.
        if std::fs::metadata(&target.abs).ok().map(|m| stamp(&m)) != before.as_ref().map(stamp) {
            out.busy = true;
            return Ok(out);
        }
        write_new(&target.abs, &merged)?;
        out.written = true;
    }
    target.store.put_yjs_base(
        target.pair,
        target.rel,
        &YjsBase {
            file_id: target.file.id.clone(),
            state: STANDARD.encode(remote.doc.state_v2()),
            seq: remote.through,
        },
    )?;
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

/// Writes `bytes` to `dest` through a temporary file beside it.
fn write_new(dest: &Path, bytes: &[u8]) -> Result<()> {
    let name = dest
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("bad file name"))?;
    let tmp = dest.with_file_name(format!(".kutup-tmp-{name}"));
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&tmp, bytes).context("write temp file")?;
    std::fs::rename(&tmp, dest).context("rename into place")?;
    Ok(())
}
