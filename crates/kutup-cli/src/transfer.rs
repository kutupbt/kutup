//! Drive revisions in the block format (docs/plans/drive-block-format.md
//! §2), as the CLI sends and reads them, with bounded memory whatever the
//! size:
//!
//! ```text
//! [header 48][block 0]…[block n−1][sealed manifest][trailer 12]
//! ```
//!
//! Upload ([`BlockSource`]): any byte range of the object, sealed from the
//! plaintext on demand, as the web's `encryptedSource.ts`. Block nonces are
//! synthetic, so sealing the same plaintext again gives the same bytes: a
//! range already sent (a resumed upload, from wherever the server stopped,
//! even inside a block) is made again by sealing from block 0. The manifest's
//! nonce is random: the tail is made once and kept by the caller before any
//! of it is sent ([`BlockSource::take_new_tail`]).
//!
//! Download ([`read_object`]): the header, the trailer and the manifest by
//! ranged reads, opened against the committed digest (the file's metadata,
//! or the revision's sealed `RevisionContent` record), then every block in
//! order, its hash and AEAD checked before any byte is written.

use std::collections::BTreeMap;
use std::io::{self, ErrorKind, Read, Write};

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::blocks::{
    block_count, block_offset, block_plaintext_len, BlockSealer, Manifest, SignerIdentity,
    BLOCK_OVERHEAD, BLOCK_SIZE, TRAILER_LEN,
};
use kutup_crypto::drive_blocks::{
    self, DriveBlobContextV2, DRIVE_BLOCKS, DRIVE_BLOCKS_HEADER_BYTES,
};
use kutup_crypto::file_metadata::ContentCommitmentV1;
use kutup_crypto::primitives::{Hasher, SigningKey, Suite};
use kutup_crypto::revision_content;

/// The whole object's length for `size` plaintext bytes: the tus
/// `Upload-Length`, known before anything is sealed.
pub fn object_len(size: u64) -> Result<i64> {
    let len = drive_blocks::blob_len(size)?;
    i64::try_from(len).map_err(|_| anyhow!("file too large"))
}

/// How many bytes one PATCH carries: two sealed blocks, above S3's 5 MiB
/// minimum for every part but the last (as the web's `PATCH_BLOCKS`).
pub const PATCH_BYTES: u64 = 2 * (BLOCK_SIZE + BLOCK_OVERHEAD) as u64;

/// How many sealed blocks stay at hand for ranges asked again.
const KEEP_BLOCKS: u64 = 4;

/// Reads into `buf` until full or EOF; the number of bytes read.
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// The file changed size while it was being uploaded.
#[derive(Debug, thiserror::Error)]
#[error("the file changed while it was being uploaded; run it again")]
pub struct ChangedWhileUploading;

/// The plaintext sealed is not the content the upload started with (its
/// SHA-256 differs from the one its metadata carries): a file changed since
/// it was hashed, or another file under the same path on resume. The upload
/// is discarded: blocks of another file may be on the server.
#[derive(Debug, thiserror::Error)]
#[error("this is not the file the upload started with; it was discarded, run it again")]
pub struct NotTheSameFile;

/// A revision's tail once made: the sealed manifest and the trailer, and
/// what the file's metadata commits to.
#[derive(Clone, Debug, PartialEq)]
pub struct KeptTail {
    pub bytes: Vec<u8>,
    pub content: ContentCommitmentV1,
}

impl KeptTail {
    /// As a resume record keeps it: the bytes and the digest, base64.
    pub fn store(&self) -> (String, String) {
        (
            STANDARD.encode(&self.bytes),
            self.content.manifest_sha256.clone(),
        )
    }

    pub fn load(bytes: &str, manifest_sha256: &str, revision_id: &str) -> Result<Self> {
        let content = ContentCommitmentV1 {
            revision_id: revision_id.to_string(),
            manifest_sha256: manifest_sha256.to_string(),
        };
        content.validate()?;
        Ok(Self {
            bytes: STANDARD.decode(bytes).context("kept tail is not base64")?,
            content,
        })
    }
}

/// Who signs the manifest: the uploader's Drive signing key and what the
/// manifest names (`drive_signer::DriveIdentity::signer`).
pub type UploadSigner<'a> = (&'a SigningKey, SignerIdentity);

struct Sealing<R> {
    sealer: BlockSealer<'static>,
    reader: R,
    hasher: Hasher,
}

/// A revision's object, made from its plaintext on demand: any byte range.
pub struct BlockSource<'a, R: Read> {
    open: Box<dyn Fn() -> Result<R> + 'a>,
    file_key: [u8; 32],
    context: DriveBlobContextV2,
    signer: UploadSigner<'a>,
    size: u64,
    count: u64,
    header: [u8; DRIVE_BLOCKS_HEADER_BYTES],
    tail_start: u64,
    total: u64,
    sealing: Option<Sealing<R>>,
    /// The block the sealer seals next.
    next: u64,
    kept: BTreeMap<u64, Vec<u8>>,
    tail: Option<KeptTail>,
    new_tail: bool,
    /// The plaintext's SHA-256 the metadata carries: the last block is not
    /// handed out unless the bytes sealed hash to it.
    sha256: [u8; 32],
    wrong: bool,
}

impl<'a, R: Read> BlockSource<'a, R> {
    /// `open` gives the plaintext from its first byte, each time it is
    /// called; `tail` is the one made before (a resumed upload's).
    pub fn new(
        open: impl Fn() -> Result<R> + 'a,
        file_key: &[u8; 32],
        context: DriveBlobContextV2,
        signer: UploadSigner<'a>,
        size: u64,
        sha256: [u8; 32],
        tail: Option<KeptTail>,
    ) -> Result<Self> {
        let count = block_count(size)?;
        let total = drive_blocks::blob_len(size)?;
        let last = count - 1;
        let tail_start = block_offset(DRIVE_BLOCKS_HEADER_BYTES, last)
            + block_plaintext_len(size, last)? as u64
            + BLOCK_OVERHEAD as u64;
        if let Some(kept) = &tail {
            if kept.bytes.len() as u64 != total - tail_start {
                bail!("the kept tail is for another object");
            }
            let revision = uuid::Uuid::from_bytes(context.revision_id)
                .hyphenated()
                .to_string();
            if kept.content.revision_id != revision {
                bail!("the kept tail is for another revision");
            }
        }
        Ok(Self {
            open: Box::new(open),
            file_key: *file_key,
            context,
            signer,
            size,
            count,
            header: drive_blocks::header(context),
            tail_start,
            total,
            sealing: None,
            next: 0,
            kept: BTreeMap::new(),
            tail,
            new_tail: false,
            sha256,
            wrong: false,
        })
    }

    /// The object's length.
    pub fn len(&self) -> u64 {
        self.total
    }

    /// What the metadata commits to, once the tail is made.
    pub fn content(&self) -> Option<&ContentCommitmentV1> {
        self.tail.as_ref().map(|tail| &tail.content)
    }

    /// The tail, once, right after it was made: keep it before sending any
    /// of it (its manifest's nonce is random, it can't be made again).
    pub fn take_new_tail(&mut self) -> Option<&KeptTail> {
        if !std::mem::take(&mut self.new_tail) {
            return None;
        }
        self.tail.as_ref()
    }

    /// Roughly how much plaintext lies before `offset` (for progress).
    pub fn plain_before(&self, offset: u64) -> u64 {
        let header = DRIVE_BLOCKS_HEADER_BYTES as u64;
        if offset <= header {
            return 0;
        }
        let stride = (BLOCK_SIZE + BLOCK_OVERHEAD) as u64;
        let sealed = offset - header;
        let blocks = sealed.div_ceil(stride);
        sealed
            .saturating_sub(blocks * BLOCK_OVERHEAD as u64)
            .min(self.size)
    }

    /// The object's bytes in `[start, end)` (cut at its end).
    pub fn bytes(&mut self, start: u64, end: u64) -> Result<Vec<u8>> {
        if self.wrong {
            return Err(NotTheSameFile.into());
        }
        let stop = end.min(self.total);
        let mut out = Vec::with_capacity(stop.saturating_sub(start) as usize);
        let mut at = start;
        let header = DRIVE_BLOCKS_HEADER_BYTES as u64;
        let stride = (BLOCK_SIZE + BLOCK_OVERHEAD) as u64;
        while at < stop {
            let (piece, from): (&[u8], u64) = if at < header {
                (&self.header[..], 0)
            } else if at >= self.tail_start {
                self.sealed_tail()?;
                let tail = self.tail.as_ref().expect("the tail was made");
                (&tail.bytes[..], self.tail_start)
            } else {
                let index = ((at - header) / stride).min(self.count - 1);
                self.block(index)?;
                let block = self.kept.get(&index).expect("the block was sealed");
                (&block[..], block_offset(DRIVE_BLOCKS_HEADER_BYTES, index))
            };
            let within = (at - from) as usize;
            let take = (piece.len() - within).min((stop - at) as usize);
            if take == 0 {
                bail!("a sealed piece is shorter than its place in the object");
            }
            out.extend_from_slice(&piece[within..within + take]);
            at += take as u64;
        }
        Ok(out)
    }

    fn block(&mut self, index: u64) -> Result<()> {
        if self.kept.contains_key(&index) {
            return Ok(());
        }
        self.seal_up_to(index)
    }

    fn restart(&mut self) -> Result<()> {
        self.sealing = Some(Sealing {
            sealer: drive_blocks::sealer(&self.file_key, self.context, self.size)?,
            reader: (self.open)()?,
            hasher: Hasher::new(Suite::V1),
        });
        self.next = 0;
        Ok(())
    }

    /// Seals on to block `index`, from the start again when it is behind.
    fn seal_up_to(&mut self, index: u64) -> Result<()> {
        if self.sealing.is_none() || self.next > index {
            self.restart()?;
        }
        while self.next <= index {
            let at = self.next;
            let len = block_plaintext_len(self.size, at)?;
            let sealing = self.sealing.as_mut().expect("sealing");
            let mut plain = vec![0u8; len];
            if read_full(&mut sealing.reader, &mut plain)? < len {
                return Err(ChangedWhileUploading.into());
            }
            sealing.hasher.update(&plain);
            let sealed = sealing.sealer.seal_next(&plain)?;
            if at + 1 == self.count {
                // Every byte was read: no more, and the content the metadata
                // names.
                let mut probe = [0u8; 1];
                if read_full(&mut sealing.reader, &mut probe)? > 0 {
                    return Err(ChangedWhileUploading.into());
                }
                let digest: [u8; 32] = sealing.hasher.clone().finish().into();
                if digest != self.sha256 {
                    self.wrong = true;
                    return Err(NotTheSameFile.into());
                }
            }
            self.kept.insert(at, sealed);
            if at >= KEEP_BLOCKS {
                self.kept.remove(&(at - KEEP_BLOCKS));
            }
            self.next = at + 1;
        }
        Ok(())
    }

    /// The tail: kept, or made once every block is sealed by one sealer.
    fn sealed_tail(&mut self) -> Result<()> {
        if self.tail.is_some() {
            return Ok(());
        }
        if self.next != self.count {
            self.seal_up_to(self.count - 1)?;
        }
        let sealing = self
            .sealing
            .take()
            .ok_or_else(|| anyhow!("the revision is not sealed to its end"))?;
        let made = sealing.sealer.finish(Some(self.signer))?;
        if made.bytes.len() as u64 != self.total - self.tail_start {
            bail!("the tail is not the length the layout gives");
        }
        self.tail = Some(KeptTail {
            bytes: made.bytes,
            content: ContentCommitmentV1::new(self.context.revision_id, made.manifest_sha256),
        });
        self.new_tail = true;
        Ok(())
    }
}

/// What a revision is sealed as, for an upload or save of a whole buffer:
/// the object and what its metadata and record commit to.
pub struct SealedRevision {
    pub bytes: Vec<u8>,
    pub content: ContentCommitmentV1,
    /// The revision's `RevisionContent` envelope (base64), sent with it.
    pub revision_content_envelope: String,
}

/// Seals a whole buffer as revision `revision_id` of `file_id` under the
/// file key of `generation`, signed by the uploader.
pub fn seal_revision(
    plaintext: &[u8],
    file_key: &[u8; 32],
    file_id: &str,
    revision_id: &str,
    generation: u32,
    signer: UploadSigner<'_>,
) -> Result<SealedRevision> {
    let context = DriveBlobContextV2::new(file_id, revision_id, generation)?;
    let sealed = drive_blocks::seal_file(plaintext, file_key, context, signer.0, signer.1)?;
    let content = ContentCommitmentV1::new(context.revision_id, sealed.manifest_sha256);
    let revision_content_envelope = seal_revision_content(
        file_key,
        file_id,
        generation,
        &content,
        plaintext.len() as u64,
    )?;
    Ok(SealedRevision {
        bytes: sealed.bytes,
        content,
        revision_content_envelope,
    })
}

/// A revision's sealed content record (base64): its id, its manifest's
/// digest and its size, under the file key of the generation that sealed it.
pub fn seal_revision_content(
    file_key: &[u8; 32],
    file_id: &str,
    generation: u32,
    content: &ContentCommitmentV1,
    size: u64,
) -> Result<String> {
    let record = revision_content::RevisionContentV1 {
        revision_id: content.revision_id.clone(),
        manifest_sha256: content.manifest_sha256.clone(),
        size,
    };
    Ok(STANDARD.encode(revision_content::seal_revision_content(
        &record, file_key, file_id, generation,
    )?))
}

// ------------------------------------------------------------------ reading

/// One byte range of an object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteRange {
    /// `bytes=a-b`, inclusive.
    Span(u64, u64),
}

/// What a ranged read answered: the bytes, the whole object's length, and
/// what the response names (`x-kutup-revision`, `x-kutup-revision-content`,
/// `x-kutup-version`).
#[derive(Clone, Debug, Default)]
pub struct Ranged {
    pub bytes: Vec<u8>,
    pub total: u64,
    pub revision: Option<String>,
    pub revision_content: Option<String>,
    pub version: Option<String>,
}

/// What the object must be to open.
#[derive(Clone, Debug)]
pub enum Expect {
    /// The file's current content: what its metadata commits to, and its
    /// size. A record served with it must agree.
    Current {
        content: ContentCommitmentV1,
        size: u64,
    },
    /// Any other revision (a version, the original, a saved state): its id
    /// and its sealed record, from a listing, or (`None`) from the response,
    /// whose revision must then be this one.
    Revision {
        revision_id: String,
        envelope: Option<String>,
    },
}

/// A revision read: its plaintext size, its manifest (for the signer
/// check), the revision and the version the response named.
pub struct Opened {
    pub size: u64,
    pub manifest: Manifest,
    pub revision_id: String,
    pub version: Option<String>,
}

fn committed(
    file_key: &[u8; 32],
    file_id: &str,
    generation: u32,
    expect: &Expect,
    first: &Ranged,
) -> Result<(ContentCommitmentV1, u64)> {
    match expect {
        Expect::Current { content, size } => {
            if let Some(envelope) = &first.revision_content {
                if first
                    .revision
                    .as_deref()
                    .is_some_and(|r| r != content.revision_id)
                {
                    bail!("the server served another revision than the metadata commits to");
                }
                let opened = revision_content::open_revision_content(
                    &STANDARD
                        .decode(envelope)
                        .context("revision record is not base64")?,
                    file_key,
                    file_id,
                    &content.revision_id,
                    generation,
                )?;
                if opened.manifest_sha256 != content.manifest_sha256 || opened.size != *size {
                    bail!("the revision's record disagrees with the file's metadata");
                }
            }
            Ok((content.clone(), *size))
        }
        Expect::Revision {
            revision_id,
            envelope,
        } => {
            if first.revision.as_deref().is_some_and(|r| r != revision_id) {
                bail!("the server served another revision than the one asked for");
            }
            let envelope = envelope
                .as_ref()
                .or(first.revision_content.as_ref())
                .ok_or_else(|| anyhow!("this revision has no committed content"))?;
            let opened = revision_content::open_revision_content(
                &STANDARD
                    .decode(envelope)
                    .context("revision record is not base64")?,
                file_key,
                file_id,
                revision_id,
                generation,
            )?;
            Ok((opened.commitment(), opened.size))
        }
    }
}

/// Reads `[start, start + len)`, in as many answers as the server cuts it
/// into.
fn fetch_exact(
    fetch: &mut impl FnMut(ByteRange) -> Result<Ranged>,
    start: u64,
    len: u64,
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(len as usize);
    while (out.len() as u64) < len {
        let at = start + out.len() as u64;
        let got = fetch(ByteRange::Span(at, start + len - 1))?;
        if got.bytes.is_empty() || got.bytes.len() as u64 > len - out.len() as u64 {
            bail!("the server answered another range than asked");
        }
        out.extend_from_slice(&got.bytes);
    }
    Ok(out)
}

/// Reads revision `expect` of `file_id`, sealed under `file_key` of
/// `generation`, writing its plaintext to `dst` block by block, each
/// checked first; `fetch` makes one ranged read.
pub fn read_object(
    mut fetch: impl FnMut(ByteRange) -> Result<Ranged>,
    file_key: &[u8; 32],
    file_id: &str,
    generation: u32,
    expect: &Expect,
    dst: &mut impl Write,
    mut on_progress: impl FnMut(u64),
) -> Result<Opened> {
    let header_len = DRIVE_BLOCKS_HEADER_BYTES as u64;
    let first = fetch(ByteRange::Span(0, header_len - 1))?;
    if first.bytes.len() as u64 != header_len {
        bail!("Drive blob header truncated");
    }
    let (content, size) = committed(file_key, file_id, generation, expect, &first)?;
    let context = DriveBlobContextV2::new(file_id, &content.revision_id, generation)?;
    drive_blocks::validate_header(&first.bytes, context)?;
    let total = first.total;
    if total < header_len + TRAILER_LEN as u64 {
        bail!("Drive blob too short");
    }
    let trailer = fetch_exact(&mut fetch, total - TRAILER_LEN as u64, TRAILER_LEN as u64)?;
    let manifest_len = DRIVE_BLOCKS.parse_trailer(&trailer)? as u64;
    let manifest_end = total - TRAILER_LEN as u64;
    let manifest_start = manifest_end
        .checked_sub(manifest_len)
        .filter(|start| *start >= header_len)
        .ok_or_else(|| anyhow!("Drive blob manifest does not fit"))?;
    let sealed_manifest = fetch_exact(&mut fetch, manifest_start, manifest_len)?;
    let reader = drive_blocks::reader(file_key, context, &sealed_manifest, &content, size)?;
    if reader.object_len()? != total {
        bail!("the Drive blob is not the length its manifest gives");
    }
    let mut written = 0u64;
    for index in 0..reader.manifest().count {
        let start = block_offset(DRIVE_BLOCKS_HEADER_BYTES, index);
        let len = block_plaintext_len(size, index)? as u64 + BLOCK_OVERHEAD as u64;
        let block = fetch_exact(&mut fetch, start, len)?;
        let plain = reader.open_block(index, &block)?;
        dst.write_all(&plain)?;
        written += plain.len() as u64;
        on_progress(written);
    }
    Ok(Opened {
        size,
        manifest: reader.manifest().clone(),
        revision_id: content.revision_id,
        version: first.version,
    })
}

/// An object held whole in memory, read as ranges (tests, and a server that
/// answered without one).
pub fn slice_whole(object: &[u8], range: ByteRange) -> Ranged {
    let total = object.len() as u64;
    let ByteRange::Span(a, b) = range;
    let (start, end) = (a.min(total), (b + 1).min(total));
    Ranged {
        bytes: object[start as usize..end.max(start) as usize].to_vec(),
        total,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "11111111-1111-4111-8111-111111111111";
    const REVISION: &str = "22222222-2222-4222-8222-222222222222";
    const KEY: [u8; 32] = [9; 32];

    fn signing() -> SigningKey {
        SigningKey::from_seed(Suite::V1, &[4; 32])
    }

    fn signer(key: &SigningKey) -> UploadSigner<'_> {
        (
            key,
            SignerIdentity {
                account_id: [3; 16],
                incarnation_id: [5; 32],
            },
        )
    }

    fn context() -> DriveBlobContextV2 {
        DriveBlobContextV2::new(FILE, REVISION, 3).unwrap()
    }

    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8 ^ seed).collect()
    }

    fn sha(plain: &[u8]) -> [u8; 32] {
        kutup_crypto::primitives::hash(Suite::V1, plain).into()
    }

    fn source<'a>(
        plain: &'a [u8],
        key: &'a SigningKey,
        tail: Option<KeptTail>,
    ) -> BlockSource<'a, &'a [u8]> {
        BlockSource::new(
            move || Ok(plain),
            &KEY,
            context(),
            signer(key),
            plain.len() as u64,
            sha(plain),
            tail,
        )
        .unwrap()
    }

    /// The whole object, sent in PATCH-sized parts from `from`.
    fn send_from(source: &mut BlockSource<'_, &[u8]>, from: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let mut at = from;
        while at < source.len() {
            let part = source.bytes(at, at + PATCH_BYTES).unwrap();
            at += part.len() as u64;
            out.extend_from_slice(&part);
        }
        out
    }

    fn read_back(object: &[u8], content: &ContentCommitmentV1, size: u64) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        read_object(
            |range| Ok(slice_whole(object, range)),
            &KEY,
            FILE,
            3,
            &Expect::Current {
                content: content.clone(),
                size,
            },
            &mut out,
            |_| {},
        )?;
        Ok(out)
    }

    #[test]
    fn every_size_goes_up_and_reads_back() {
        let key = signing();
        for size in [
            0,
            1,
            BLOCK_SIZE - 1,
            BLOCK_SIZE,
            BLOCK_SIZE + 1,
            2 * BLOCK_SIZE + 17,
        ] {
            let plain = pattern(size, 1);
            let mut up = source(&plain, &key, None);
            assert_eq!(up.len() as i64, object_len(size as u64).unwrap());
            let object = send_from(&mut up, 0);
            assert_eq!(object.len() as u64, up.len());
            let content = up.content().unwrap().clone();
            assert_eq!(
                read_back(&object, &content, size as u64).unwrap(),
                plain,
                "{size}"
            );
            // Another size than the metadata's, or another digest, opens nothing.
            assert!(read_back(&object, &content, size as u64 + 1).is_err());
            let other = ContentCommitmentV1::new(context().revision_id, [0; 32]);
            assert!(read_back(&object, &other, size as u64).is_err());
        }
    }

    /// An upload cut at any offset (inside the header, a block, or the
    /// tail) goes on by sealing again from block 0; the bytes are the same.
    #[test]
    fn a_resume_from_any_offset_sends_the_same_bytes() {
        let key = signing();
        let plain = pattern(2 * BLOCK_SIZE + 777, 2);
        let mut first = source(&plain, &key, None);
        let whole = send_from(&mut first, 0);
        let tail = first.tail.clone().unwrap();
        let tail_start = first.tail_start;
        for offset in [
            0,
            17,
            DRIVE_BLOCKS_HEADER_BYTES as u64,
            DRIVE_BLOCKS_HEADER_BYTES as u64 + 5,
            PATCH_BYTES,
            PATCH_BYTES - 12_345,
            tail_start - 1,
            tail_start,
            tail_start + 3,
            whole.len() as u64 - 1,
        ] {
            let mut resumed = source(&plain, &key, Some(tail.clone()));
            let rest = send_from(&mut resumed, offset);
            assert_eq!(rest, whole[offset as usize..], "offset {offset}");
            assert!(resumed.take_new_tail().is_none(), "the kept tail is sent");
        }
        // Asked again for a range behind the sealer: sealed again from 0.
        let mut again = source(&plain, &key, Some(tail));
        let late = again.bytes(tail_start - 10, tail_start + 5).unwrap();
        let early = again.bytes(0, 100).unwrap();
        assert_eq!(
            late,
            whole[tail_start as usize - 10..tail_start as usize + 5]
        );
        assert_eq!(early, whole[..100]);
    }

    #[test]
    fn the_tail_is_made_once_and_handed_out_to_keep() {
        let key = signing();
        let plain = pattern(100, 3);
        let mut up = source(&plain, &key, None);
        assert!(up.take_new_tail().is_none());
        let _ = up.bytes(0, up.len()).unwrap();
        let tail = up.take_new_tail().cloned().expect("made");
        assert!(up.take_new_tail().is_none(), "only once");
        let (bytes, digest) = tail.store();
        assert_eq!(KeptTail::load(&bytes, &digest, REVISION).unwrap(), tail);
        // A tail for another revision or length is refused.
        assert!(BlockSource::new(
            || Ok(&plain[..]),
            &KEY,
            DriveBlobContextV2::new(FILE, "44444444-4444-4444-8444-444444444444", 3).unwrap(),
            signer(&key),
            100,
            sha(&plain),
            Some(tail.clone()),
        )
        .is_err());
        assert!(BlockSource::new(
            || Ok(&plain[..]),
            &KEY,
            context(),
            signer(&key),
            BLOCK_SIZE as u64 + 100,
            sha(&plain),
            Some(tail),
        )
        .is_err());
    }

    /// Another file of the same size under the record (or a file changed
    /// since it was hashed): the last block is never handed out, and nothing
    /// more after.
    #[test]
    fn another_file_on_resume_is_not_the_same_file() {
        let key = signing();
        let started = pattern(BLOCK_SIZE + 10, 4);
        let other = pattern(BLOCK_SIZE + 10, 5);
        let mut up = BlockSource::new(
            || Ok(&other[..]),
            &KEY,
            context(),
            signer(&key),
            other.len() as u64,
            sha(&started),
            None,
        )
        .unwrap();
        // The first block goes (the plaintext can't be told yet)…
        assert!(up.bytes(0, PATCH_BYTES / 2).is_ok());
        // …the last does not.
        let error = up.bytes(0, up.len()).unwrap_err();
        assert!(error.is::<NotTheSameFile>(), "{error:#}");
        assert!(up.bytes(0, 10).unwrap_err().is::<NotTheSameFile>());
    }

    #[test]
    fn a_file_that_shrinks_or_grows_stops_the_upload() {
        let key = signing();
        let plain = pattern(100, 6);
        let shorter = &plain[..60];
        let mut up = BlockSource::new(
            || Ok(shorter),
            &KEY,
            context(),
            signer(&key),
            100,
            sha(&plain),
            None,
        )
        .unwrap();
        assert!(up.bytes(0, 200).unwrap_err().is::<ChangedWhileUploading>());
        let mut up = BlockSource::new(
            || Ok(&plain[..]),
            &KEY,
            context(),
            signer(&key),
            60,
            sha(&plain[..60]),
            None,
        )
        .unwrap();
        assert!(up.bytes(0, 200).unwrap_err().is::<ChangedWhileUploading>());
    }

    #[test]
    fn a_version_reads_against_its_record_and_the_served_revision() {
        let key = signing();
        let plain = pattern(5000, 7);
        let sealed = seal_revision(&plain, &KEY, FILE, REVISION, 3, signer(&key)).unwrap();
        let read = |expect: &Expect, served: Option<&str>| {
            let mut out = Vec::new();
            read_object(
                |range| {
                    let mut ranged = slice_whole(&sealed.bytes, range);
                    ranged.revision = served.map(str::to_string);
                    ranged.revision_content = Some(sealed.revision_content_envelope.clone());
                    Ok(ranged)
                },
                &KEY,
                FILE,
                3,
                expect,
                &mut out,
                |_| {},
            )
            .map(|_| out)
        };
        let by_listing = Expect::Revision {
            revision_id: REVISION.into(),
            envelope: Some(sealed.revision_content_envelope.clone()),
        };
        assert_eq!(read(&by_listing, Some(REVISION)).unwrap(), plain);
        let by_response = Expect::Revision {
            revision_id: REVISION.into(),
            envelope: None,
        };
        assert_eq!(read(&by_response, None).unwrap(), plain);
        // The server serving another revision than the metadata names.
        assert!(read(&by_response, Some("44444444-4444-4444-8444-444444444444")).is_err());
        // Read as another revision: the record is bound to this one.
        let other = Expect::Revision {
            revision_id: "44444444-4444-4444-8444-444444444444".into(),
            envelope: Some(sealed.revision_content_envelope.clone()),
        };
        assert!(read(&other, None).is_err());
        // The current content: a served record must agree with the metadata.
        let current = Expect::Current {
            content: sealed.content.clone(),
            size: plain.len() as u64,
        };
        assert_eq!(read(&current, Some(REVISION)).unwrap(), plain);
        let wrong_size = Expect::Current {
            content: sealed.content.clone(),
            size: plain.len() as u64 - 1,
        };
        assert!(read(&wrong_size, Some(REVISION)).is_err());
    }
}
