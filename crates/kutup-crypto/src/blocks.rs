//! One seekable block framing for every large object
//! (docs/plans/drive-block-format.md §2): fixed 4 MiB blocks, each sealed on
//! its own and bound to its index, whether it is the last, and the object's
//! header; a manifest of the blocks' hashes that fixes the size and the end,
//! sealed after the last block (and, for Drive, signed by the uploader); and a
//! trailer that says where the manifest starts.
//!
//! ```text
//! [header][block 0]…[block n−1][sealed manifest][trailer 12]
//! ```
//!
//! A family (a Drive blob, a Chat attachment, a Chat backup media object)
//! brings its own header, labels and trailer magic, and whether its manifest
//! is signed; nothing else differs. Each family's keys are derived from its
//! own key material with its own labels and its header as the HKDF info, so
//! no key, header or suite is shared between families or objects.

use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::primitives::{hash, mac, Aead, Kdf, SigningKey, Suite, VerifyingKey};

/// Plaintext bytes per block: a fact of every block suite (Proton's 4 MiB).
pub const BLOCK_SIZE: usize = 4 * 1024 * 1024;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
/// What sealing adds to a block: its nonce and its tag.
pub const BLOCK_OVERHEAD: usize = NONCE_LEN + TAG_LEN;
pub const HASH_LEN: usize = 32;
/// `u32 sealed-manifest length ‖ 8-byte magic`.
pub const TRAILER_LEN: usize = 12;
/// The most blocks an object may have: 4 TiB, far past any upload limit, so
/// a forged trailer can't make a reader allocate without bound.
pub const MAX_BLOCKS: u64 = 1 << 20;

const KEY_LEN: usize = 32;
const MANIFEST_FIXED_LEN: usize = 4 + 4 + 8;
const SIGNER_NONE: u8 = 0;
const SIGNER_DRIVE_SIGNING_KEY: u8 = 1;
const ACCOUNT_LEN: usize = 16;
const SIGNATURE_LEN: usize = 64;
const MANIFEST_AAD_LABEL: &[u8] = b"manifest";

/// What a family brings to the shared construction.
#[derive(Debug)]
pub struct BlockFamily {
    pub block_key_label: &'static [u8],
    pub nonce_key_label: &'static [u8],
    pub manifest_key_label: &'static [u8],
    /// The signed message's domain (signed families only).
    pub signature_domain: &'static [u8],
    pub trailer_magic: &'static [u8; 8],
    /// Whether the manifest carries the uploader's signature.
    pub signed: bool,
}

impl BlockFamily {
    fn signer_len(&self) -> usize {
        1 + if self.signed {
            ACCOUNT_LEN + SIGNATURE_LEN
        } else {
            0
        }
    }

    /// The manifest's plaintext length for `count` blocks.
    pub fn manifest_plaintext_len(&self, count: u64) -> Result<usize> {
        if count == 0 || count > MAX_BLOCKS {
            return Err(CryptoError::InvalidInput(
                "a block object has 1 to MAX_BLOCKS blocks".into(),
            ));
        }
        Ok(MANIFEST_FIXED_LEN + count as usize * HASH_LEN + self.signer_len())
    }

    /// The sealed manifest's length for `count` blocks.
    pub fn sealed_manifest_len(&self, count: u64) -> Result<usize> {
        Ok(NONCE_LEN + self.manifest_plaintext_len(count)? + TAG_LEN)
    }

    /// The whole object's length for `size` plaintext bytes behind a header of
    /// `header_len` bytes: exact, as an upload needs it before sealing.
    pub fn object_len(&self, header_len: usize, size: u64) -> Result<u64> {
        let count = block_count(size)?;
        let body = size
            .checked_add(count * BLOCK_OVERHEAD as u64)
            .ok_or_else(|| CryptoError::InvalidInput("block object too large".into()))?;
        Ok(header_len as u64 + body + self.sealed_manifest_len(count)? as u64 + TRAILER_LEN as u64)
    }

    /// From a stored object's total length and its trailer's manifest length:
    /// the block count, if the structure holds (the server's check; it can't
    /// check the AEAD).
    pub fn check_structure(
        &self,
        header_len: usize,
        total_len: u64,
        sealed_manifest_len: usize,
    ) -> Result<u64> {
        let fixed = NONCE_LEN + MANIFEST_FIXED_LEN + self.signer_len() + TAG_LEN;
        if sealed_manifest_len < fixed + HASH_LEN
            || !(sealed_manifest_len - fixed).is_multiple_of(HASH_LEN)
        {
            return Err(CryptoError::InvalidInput(
                "block object manifest length is malformed".into(),
            ));
        }
        let count = ((sealed_manifest_len - fixed) / HASH_LEN) as u64;
        if count > MAX_BLOCKS {
            return Err(CryptoError::InvalidInput(
                "block object has too many blocks".into(),
            ));
        }
        let body = total_len
            .checked_sub(header_len as u64 + sealed_manifest_len as u64 + TRAILER_LEN as u64)
            .ok_or(CryptoError::TooShort)?;
        // n − 1 full blocks and a last one of 0 to B plaintext bytes.
        let full = (count - 1) * (BLOCK_SIZE + BLOCK_OVERHEAD) as u64;
        let last = body.checked_sub(full).ok_or(CryptoError::TooShort)?;
        if !(BLOCK_OVERHEAD as u64..=(BLOCK_SIZE + BLOCK_OVERHEAD) as u64).contains(&last) {
            return Err(CryptoError::InvalidInput(
                "block object length does not fit its block count".into(),
            ));
        }
        Ok(count)
    }

    /// The sealed manifest's length a trailer names, checked against the
    /// family's magic and the largest manifest.
    pub fn parse_trailer(&self, trailer: &[u8]) -> Result<usize> {
        if trailer.len() != TRAILER_LEN || &trailer[4..] != self.trailer_magic {
            return Err(CryptoError::InvalidInput(
                "block object trailer is malformed".into(),
            ));
        }
        let len = u32::from_be_bytes(trailer[..4].try_into().expect("four bytes")) as usize;
        if len > self.sealed_manifest_len(MAX_BLOCKS)? || len < self.sealed_manifest_len(1)? {
            return Err(CryptoError::InvalidInput(
                "block object manifest length is out of range".into(),
            ));
        }
        Ok(len)
    }
}

/// Blocks for `size` plaintext bytes: at least one (an empty object is one
/// empty last block).
pub fn block_count(size: u64) -> Result<u64> {
    let count = size.div_ceil(BLOCK_SIZE as u64).max(1);
    if count > MAX_BLOCKS {
        return Err(CryptoError::InvalidInput("block object too large".into()));
    }
    Ok(count)
}

/// Plaintext bytes in block `index` of an object of `size` bytes.
pub fn block_plaintext_len(size: u64, index: u64) -> Result<usize> {
    let count = block_count(size)?;
    if index >= count {
        return Err(CryptoError::InvalidInput("block index out of range".into()));
    }
    let start = index * BLOCK_SIZE as u64;
    Ok((size - start).min(BLOCK_SIZE as u64) as usize)
}

/// Where block `index` starts in the object, behind a header of
/// `header_len` bytes (every block before it is full).
pub fn block_offset(header_len: usize, index: u64) -> u64 {
    header_len as u64 + index * (BLOCK_SIZE + BLOCK_OVERHEAD) as u64
}

/// The keys of one object: derived from the family's key material with its
/// labels, the object's header as the info, so each object has its own.
pub struct BlockKeys {
    block: Aead,
    nonce: Zeroizing<[u8; KEY_LEN]>,
    manifest: Aead,
}

impl BlockKeys {
    pub fn derive(family: &BlockFamily, ikm: &[u8], header: &[u8]) -> Result<Self> {
        if ikm.len() != KEY_LEN {
            return Err(CryptoError::InvalidLength {
                expected: KEY_LEN,
                got: ikm.len(),
            });
        }
        Ok(Self {
            block: Aead::new(
                Suite::V1,
                derive_key(family.block_key_label, ikm, header)?.as_slice(),
            )?,
            nonce: derive_key(family.nonce_key_label, ikm, header)?,
            manifest: Aead::new(
                Suite::V1,
                derive_key(family.manifest_key_label, ikm, header)?.as_slice(),
            )?,
        })
    }

    /// The block, nonce and manifest keys' bytes, for the checked-in vectors
    /// only.
    #[cfg(any(test, feature = "test-vectors"))]
    pub fn derived_bytes(
        family: &BlockFamily,
        ikm: &[u8],
        header: &[u8],
    ) -> Result<[Zeroizing<[u8; KEY_LEN]>; 3]> {
        Ok([
            derive_key(family.block_key_label, ikm, header)?,
            derive_key(family.nonce_key_label, ikm, header)?,
            derive_key(family.manifest_key_label, ikm, header)?,
        ])
    }
}

/// One key of an object: HKDF with the family's label as the salt and the
/// object's header as the info.
fn derive_key(label: &[u8], ikm: &[u8], header: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Kdf::new(Suite::V1, label, ikm).expand(header, key.as_mut_slice())?;
    Ok(key)
}

fn block_aad(header: &[u8], index: u64, last: bool) -> Result<Vec<u8>> {
    let index = u32::try_from(index)
        .map_err(|_| CryptoError::InvalidInput("block index out of range".into()))?;
    Ok([header, &index.to_be_bytes(), &[u8::from(last)]].concat())
}

/// The block's nonce: synthetic over its index, `last` and its plaintext, so
/// the same block seals to the same bytes (an upload resumes anywhere) and a
/// changed one never reuses a nonce.
fn block_nonce(
    keys: &BlockKeys,
    index: u64,
    last: bool,
    plaintext: &[u8],
) -> Result<[u8; NONCE_LEN]> {
    let index = u32::try_from(index)
        .map_err(|_| CryptoError::InvalidInput("block index out of range".into()))?;
    let tag = mac(
        Suite::V1,
        keys.nonce.as_slice(),
        &[
            &index.to_be_bytes(),
            &[u8::from(last)],
            &hash(Suite::V1, plaintext),
        ],
    );
    Ok(tag.as_bytes()[..NONCE_LEN]
        .try_into()
        .expect("a MAC is longer than a nonce"))
}

/// Seals block `index` (`last` for the final one): `nonce ‖ ciphertext ‖ tag`.
pub fn seal_block(
    keys: &BlockKeys,
    header: &[u8],
    index: u64,
    last: bool,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if plaintext.len() > BLOCK_SIZE || (!last && plaintext.len() != BLOCK_SIZE) {
        return Err(CryptoError::InvalidInput(
            "only the last block may be shorter than the block size".into(),
        ));
    }
    let nonce = block_nonce(keys, index, last, plaintext)?;
    let sealed = keys
        .block
        .seal_with_nonce(&nonce, &block_aad(header, index, last)?, plaintext)?;
    Ok([nonce.as_slice(), &sealed].concat())
}

/// Opens block `index`; fails for another index, header, key, or `last`.
pub fn open_block(
    keys: &BlockKeys,
    header: &[u8],
    index: u64,
    last: bool,
    block: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if block.len() < BLOCK_OVERHEAD || block.len() > BLOCK_SIZE + BLOCK_OVERHEAD {
        return Err(CryptoError::InvalidLength {
            expected: BLOCK_SIZE + BLOCK_OVERHEAD,
            got: block.len(),
        });
    }
    let (nonce, sealed) = block.split_at(NONCE_LEN);
    let plaintext = keys
        .block
        .open_with_nonce(nonce, &block_aad(header, index, last)?, sealed)
        .map_err(|_| CryptoError::AuthFailed)?;
    if !last && plaintext.len() != BLOCK_SIZE {
        return Err(CryptoError::AuthFailed);
    }
    Ok(plaintext)
}

/// Who signed a manifest: an account's Drive signing key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestSigner {
    pub account_id: [u8; ACCOUNT_LEN],
    pub signature: [u8; SIGNATURE_LEN],
}

/// An opened manifest: the size, the block count and each block's hash, and
/// for a signed family its signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub size: u64,
    pub count: u64,
    pub hashes: Vec<[u8; HASH_LEN]>,
    pub signer: Option<ManifestSigner>,
    signed_message: Vec<u8>,
}

impl Manifest {
    /// Checks the uploader's signature with `key` (the caller's pins decide
    /// what follows from it, as Drive's other signatures).
    pub fn verify_signer(&self, key: &VerifyingKey) -> Result<()> {
        let signer = self
            .signer
            .as_ref()
            .ok_or_else(|| CryptoError::InvalidInput("the manifest is not signed".into()))?;
        key.verify(&self.signed_message, &signer.signature)
    }
}

/// What a signed family's uploader signs: the domain, the header, the
/// account it names as the signer, and the manifest's fields.
fn signed_message(
    family: &BlockFamily,
    header: &[u8],
    account_id: &[u8; ACCOUNT_LEN],
    size: u64,
    hashes: &[[u8; HASH_LEN]],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        family.signature_domain.len()
            + header.len()
            + ACCOUNT_LEN
            + MANIFEST_FIXED_LEN
            + hashes.len() * HASH_LEN,
    );
    message.extend_from_slice(family.signature_domain);
    message.extend_from_slice(header);
    message.extend_from_slice(account_id);
    message.extend_from_slice(&(BLOCK_SIZE as u32).to_be_bytes());
    message.extend_from_slice(&(hashes.len() as u32).to_be_bytes());
    message.extend_from_slice(&size.to_be_bytes());
    for block_hash in hashes {
        message.extend_from_slice(block_hash);
    }
    message
}

fn manifest_aad(header: &[u8]) -> Vec<u8> {
    [header, MANIFEST_AAD_LABEL].concat()
}

/// Seals block after block, keeping their hashes, then the manifest and the
/// trailer. The plaintext size is fixed first: the ciphertext size is known
/// before sealing, as an upload needs.
pub struct BlockSealer<'a> {
    family: &'a BlockFamily,
    keys: BlockKeys,
    header: Vec<u8>,
    size: u64,
    count: u64,
    hashes: Vec<[u8; HASH_LEN]>,
}

impl<'a> BlockSealer<'a> {
    pub fn new(family: &'a BlockFamily, ikm: &[u8], header: &[u8], size: u64) -> Result<Self> {
        let count = block_count(size)?;
        Ok(Self {
            family,
            keys: BlockKeys::derive(family, ikm, header)?,
            header: header.to_vec(),
            size,
            count,
            hashes: Vec::with_capacity(count as usize),
        })
    }

    /// The index the next block takes.
    pub fn next_index(&self) -> u64 {
        self.hashes.len() as u64
    }

    /// Seals the next block, which must hold exactly its share of the size.
    pub fn seal_next(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let index = self.next_index();
        if index >= self.count {
            return Err(CryptoError::InvalidInput(
                "every block is sealed already".into(),
            ));
        }
        if plaintext.len() != block_plaintext_len(self.size, index)? {
            return Err(CryptoError::InvalidInput(
                "a block holds its share of the size, no more and no less".into(),
            ));
        }
        let block = seal_block(
            &self.keys,
            &self.header,
            index,
            index + 1 == self.count,
            plaintext,
        )?;
        self.hashes.push(hash(Suite::V1, &block).to_array());
        Ok(block)
    }

    /// The sealed manifest and the trailer, once every block is sealed; a
    /// signed family takes the uploader's key and account.
    pub fn finish(self, signer: Option<(&SigningKey, [u8; ACCOUNT_LEN])>) -> Result<SealedTail> {
        let mut nonce = [0u8; NONCE_LEN];
        crate::primitives::random(&mut nonce);
        self.finish_with_nonce(signer, &nonce)
    }

    /// [`Self::finish`] with a given manifest nonce, for the checked-in
    /// vectors only.
    #[cfg(any(test, feature = "test-vectors"))]
    pub fn finish_with_fixed_nonce(
        self,
        signer: Option<(&SigningKey, [u8; ACCOUNT_LEN])>,
        nonce: &[u8; NONCE_LEN],
    ) -> Result<SealedTail> {
        self.finish_with_nonce(signer, nonce)
    }

    fn finish_with_nonce(
        self,
        signer: Option<(&SigningKey, [u8; ACCOUNT_LEN])>,
        nonce: &[u8; NONCE_LEN],
    ) -> Result<SealedTail> {
        if self.next_index() != self.count {
            return Err(CryptoError::InvalidInput(
                "the manifest comes after every block".into(),
            ));
        }
        let mut plaintext = Zeroizing::new(Vec::with_capacity(
            self.family.manifest_plaintext_len(self.count)?,
        ));
        plaintext.extend_from_slice(&(BLOCK_SIZE as u32).to_be_bytes());
        plaintext.extend_from_slice(&(self.count as u32).to_be_bytes());
        plaintext.extend_from_slice(&self.size.to_be_bytes());
        for block_hash in &self.hashes {
            plaintext.extend_from_slice(block_hash);
        }
        match (self.family.signed, signer) {
            (true, Some((key, account_id))) => {
                let signature: [u8; SIGNATURE_LEN] = key.sign_array(&signed_message(
                    self.family,
                    &self.header,
                    &account_id,
                    self.size,
                    &self.hashes,
                ));
                plaintext.push(SIGNER_DRIVE_SIGNING_KEY);
                plaintext.extend_from_slice(&account_id);
                plaintext.extend_from_slice(&signature);
            }
            (false, None) => plaintext.push(SIGNER_NONE),
            _ => {
                return Err(CryptoError::InvalidInput(
                    "a signed family's manifest is signed, another's is not".into(),
                ))
            }
        }
        let mut tail = seal_manifest(&self.keys, &self.header, &plaintext, nonce)?;
        let manifest_sha256 = manifest_digest(&tail);
        let len = u32::try_from(tail.len())
            .map_err(|_| CryptoError::InvalidInput("manifest too large".into()))?;
        tail.extend_from_slice(&len.to_be_bytes());
        tail.extend_from_slice(self.family.trailer_magic);
        Ok(SealedTail {
            bytes: tail,
            manifest_sha256,
        })
    }
}

/// What follows the last block: the sealed manifest and the trailer, and the
/// sealed manifest's digest, which the object's metadata or descriptor
/// commits to and every reader requires.
pub struct SealedTail {
    pub bytes: Vec<u8>,
    pub manifest_sha256: [u8; HASH_LEN],
}

/// The sealed manifest's SHA-256: what a sealed metadata or descriptor
/// commits to.
pub fn manifest_digest(sealed_manifest: &[u8]) -> [u8; HASH_LEN] {
    hash(Suite::V1, sealed_manifest).to_array()
}

fn seal_manifest(
    keys: &BlockKeys,
    header: &[u8],
    plaintext: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    let mut sealed = nonce.to_vec();
    sealed.extend_from_slice(&keys.manifest.seal_with_nonce(
        nonce,
        &manifest_aad(header),
        plaintext,
    )?);
    Ok(sealed)
}

/// Seals any `plaintext` as the manifest of the object behind `header`, for
/// tests and the fuzz target only: a key holder's malformed manifest that
/// still passes the AEAD.
#[cfg(any(test, feature = "test-vectors"))]
pub fn seal_manifest_plaintext(
    family: &BlockFamily,
    ikm: &[u8],
    header: &[u8],
    plaintext: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    seal_manifest(
        &BlockKeys::derive(family, ikm, header)?,
        header,
        plaintext,
        nonce,
    )
}

/// An object's reader: its manifest opened and checked, then any block opened
/// by index, its hash checked first. Nothing is released unverified.
pub struct BlockReader<'a> {
    family: &'a BlockFamily,
    keys: BlockKeys,
    header: Vec<u8>,
    manifest: Manifest,
}

impl<'a> BlockReader<'a> {
    /// Opens the manifest of the object behind `header` (the caller has
    /// checked the header against what it expects). `sealed_manifest` is
    /// what the trailer pointed at; it must be the one the caller's metadata
    /// or descriptor commits to (`expected_manifest_sha256`), checked before
    /// anything is opened. A key holder can seal another valid object under
    /// the same header (an older revision, a shorter copy); only that
    /// commitment tells them apart.
    pub fn open(
        family: &'a BlockFamily,
        ikm: &[u8],
        header: &[u8],
        sealed_manifest: &[u8],
        expected_manifest_sha256: &[u8; HASH_LEN],
    ) -> Result<Self> {
        if sealed_manifest.len() < family.sealed_manifest_len(1)?
            || sealed_manifest.len() > family.sealed_manifest_len(MAX_BLOCKS)?
        {
            return Err(CryptoError::InvalidInput(
                "block object manifest length is out of range".into(),
            ));
        }
        if !crate::primitives::ct_eq(&manifest_digest(sealed_manifest), expected_manifest_sha256) {
            return Err(CryptoError::AuthFailed);
        }
        let keys = BlockKeys::derive(family, ikm, header)?;
        let plaintext = keys
            .manifest
            .open(&manifest_aad(header), sealed_manifest)
            .map_err(|_| CryptoError::AuthFailed)?;
        let manifest = parse_manifest(family, header, &plaintext)?;
        Ok(Self {
            family,
            keys,
            header: header.to_vec(),
            manifest,
        })
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The whole object's length, as the manifest fixes it.
    pub fn object_len(&self) -> Result<u64> {
        self.family
            .object_len(self.header.len(), self.manifest.size)
    }

    /// Opens block `index`: its hash against the manifest first, then its
    /// AEAD at its index, `last` only for the final block.
    pub fn open_block(&self, index: u64, block: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let expected = self
            .manifest
            .hashes
            .get(usize::try_from(index).map_err(|_| CryptoError::AuthFailed)?)
            .ok_or_else(|| CryptoError::InvalidInput("block index out of range".into()))?;
        if &hash(Suite::V1, block).to_array() != expected {
            return Err(CryptoError::AuthFailed);
        }
        let plaintext = open_block(
            &self.keys,
            &self.header,
            index,
            index + 1 == self.manifest.count,
            block,
        )?;
        if plaintext.len() != block_plaintext_len(self.manifest.size, index)? {
            return Err(CryptoError::AuthFailed);
        }
        Ok(plaintext)
    }
}

fn parse_manifest(family: &BlockFamily, header: &[u8], plaintext: &[u8]) -> Result<Manifest> {
    let malformed = || CryptoError::InvalidInput("block object manifest is malformed".into());
    if plaintext.len() < MANIFEST_FIXED_LEN {
        return Err(malformed());
    }
    let block_size = u32::from_be_bytes(plaintext[0..4].try_into().expect("four bytes"));
    let count = u64::from(u32::from_be_bytes(
        plaintext[4..8].try_into().expect("four bytes"),
    ));
    let size = u64::from_be_bytes(plaintext[8..16].try_into().expect("eight bytes"));
    if block_size as usize != BLOCK_SIZE
        || count != block_count(size)?
        || plaintext.len() != family.manifest_plaintext_len(count)?
    {
        return Err(malformed());
    }
    let hashes_end = MANIFEST_FIXED_LEN + count as usize * HASH_LEN;
    let hashes: Vec<[u8; HASH_LEN]> = plaintext[MANIFEST_FIXED_LEN..hashes_end]
        .as_chunks::<HASH_LEN>()
        .0
        .to_vec();
    let signer_bytes = &plaintext[hashes_end..];
    let signer = match (family.signed, signer_bytes) {
        (true, [SIGNER_DRIVE_SIGNING_KEY, rest @ ..])
            if rest.len() == ACCOUNT_LEN + SIGNATURE_LEN =>
        {
            Some(ManifestSigner {
                account_id: rest[..ACCOUNT_LEN].try_into().expect("an account id"),
                signature: rest[ACCOUNT_LEN..].try_into().expect("a signature"),
            })
        }
        (false, [SIGNER_NONE]) => None,
        _ => return Err(malformed()),
    };
    let signed_message = signer.as_ref().map_or_else(Vec::new, |signer| {
        signed_message(family, header, &signer.account_id, size, &hashes)
    });
    Ok(Manifest {
        size,
        count,
        signed_message,
        hashes,
        signer,
    })
}

/// Seals a whole buffer: the same construction, so there is one format, not
/// a small one.
pub fn seal_object(
    family: &BlockFamily,
    ikm: &[u8],
    header: &[u8],
    plaintext: &[u8],
    signer: Option<(&SigningKey, [u8; ACCOUNT_LEN])>,
) -> Result<SealedObject> {
    let mut sealer = BlockSealer::new(family, ikm, header, plaintext.len() as u64)?;
    let mut object =
        Vec::with_capacity(family.object_len(header.len(), plaintext.len() as u64)? as usize);
    object.extend_from_slice(header);
    if plaintext.is_empty() {
        object.extend_from_slice(&sealer.seal_next(&[])?);
    }
    for chunk in plaintext.chunks(BLOCK_SIZE) {
        object.extend_from_slice(&sealer.seal_next(chunk)?);
    }
    let tail = sealer.finish(signer)?;
    object.extend_from_slice(&tail.bytes);
    Ok(SealedObject {
        bytes: object,
        manifest_sha256: tail.manifest_sha256,
    })
}

/// A whole sealed object and its sealed manifest's digest (see
/// [`SealedTail`]).
#[derive(Debug)]
pub struct SealedObject {
    pub bytes: Vec<u8>,
    pub manifest_sha256: [u8; HASH_LEN],
}

/// The sealed manifest's digest of a whole object, from its trailer (not yet
/// checked against anything: a caller compares it with its commitment).
pub fn object_manifest_digest(
    object: &[u8],
    header_len: usize,
    family: &BlockFamily,
) -> Result<[u8; HASH_LEN]> {
    let (start, end) = manifest_range(family, header_len, object)?;
    Ok(manifest_digest(&object[start..end]))
}

/// Where a whole object's sealed manifest sits, from its trailer.
fn manifest_range(
    family: &BlockFamily,
    header_len: usize,
    object: &[u8],
) -> Result<(usize, usize)> {
    if object.len() < header_len + TRAILER_LEN {
        return Err(CryptoError::TooShort);
    }
    let end = object.len() - TRAILER_LEN;
    let len = family.parse_trailer(&object[end..])?;
    let start = end
        .checked_sub(len)
        .filter(|start| *start >= header_len)
        .ok_or(CryptoError::TooShort)?;
    Ok((start, end))
}

/// Opens a whole object whose header (`header_len` bytes, first) the caller
/// has checked and whose sealed manifest is the committed one: its
/// manifest, then every block in order. The plaintext and the manifest, for
/// the caller's signature check.
pub fn open_object(
    family: &BlockFamily,
    ikm: &[u8],
    header_len: usize,
    object: &[u8],
    expected_manifest_sha256: &[u8; HASH_LEN],
) -> Result<(Zeroizing<Vec<u8>>, Manifest)> {
    let (manifest_start, manifest_end) = manifest_range(family, header_len, object)?;
    let count = family.check_structure(
        header_len,
        object.len() as u64,
        manifest_end - manifest_start,
    )?;
    let reader = BlockReader::open(
        family,
        ikm,
        &object[..header_len],
        &object[manifest_start..manifest_end],
        expected_manifest_sha256,
    )?;
    if reader.manifest().count != count || reader.object_len()? != object.len() as u64 {
        return Err(CryptoError::InvalidInput(
            "block object length does not match its manifest".into(),
        ));
    }
    let mut plaintext = Zeroizing::new(Vec::with_capacity(reader.manifest().size as usize));
    for index in 0..count {
        let start = block_offset(header_len, index) as usize;
        let len = block_plaintext_len(reader.manifest().size, index)? + BLOCK_OVERHEAD;
        let block = object
            .get(start..start + len)
            .ok_or(CryptoError::TooShort)?;
        plaintext.extend_from_slice(&reader.open_block(index, block)?);
    }
    Ok((plaintext, reader.manifest().clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat_media::ChatMediaObjectContextV1;
    use crate::chat_media_blocks::{self, CHAT_MEDIA_BLOCKS};
    use crate::drive_blocks::{self, DriveBlobContextV2, DRIVE_BLOCKS};

    const KEY: [u8; 32] = [7; 32];
    const NONCE: [u8; NONCE_LEN] = [1; NONCE_LEN];
    const B: u64 = BLOCK_SIZE as u64;

    fn chat_header() -> Vec<u8> {
        chat_media_blocks::header(
            ChatMediaObjectContextV1::new("66666666-6666-4666-8666-666666666666").unwrap(),
        )
        .to_vec()
    }

    fn drive_header() -> Vec<u8> {
        drive_blocks::header(
            DriveBlobContextV2::new(
                "11111111-1111-4111-8111-111111111111",
                "22222222-2222-4222-8222-222222222222",
                1,
            )
            .unwrap(),
        )
        .to_vec()
    }

    /// A manifest plaintext from its fields, as a key holder could write it.
    fn manifest(block_size: u32, count: u32, size: u64, signer: &[u8]) -> Vec<u8> {
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&block_size.to_be_bytes());
        plaintext.extend_from_slice(&count.to_be_bytes());
        plaintext.extend_from_slice(&size.to_be_bytes());
        for index in 0..count {
            plaintext.extend_from_slice(&[index as u8; HASH_LEN]);
        }
        plaintext.extend_from_slice(signer);
        plaintext
    }

    /// Opens `plaintext` sealed as a manifest: it passes the AEAD and the
    /// commitment, so only the parse decides.
    fn open(family: &BlockFamily, header: &[u8], plaintext: &[u8]) -> Result<BlockReader<'static>>
    where
        BlockFamily: 'static,
    {
        let family: &'static BlockFamily = if family.signed {
            &DRIVE_BLOCKS
        } else {
            &CHAT_MEDIA_BLOCKS
        };
        let sealed = seal_manifest_plaintext(family, &KEY, header, plaintext, &NONCE).unwrap();
        BlockReader::open(family, &KEY, header, &sealed, &manifest_digest(&sealed))
    }

    #[test]
    fn a_key_holders_malformed_manifest_is_refused() {
        let header = chat_header();
        let none = [SIGNER_NONE];
        assert!(open(
            &CHAT_MEDIA_BLOCKS,
            &header,
            &manifest(B as u32, 2, B + 1, &none)
        )
        .is_ok());
        for (why, plaintext) in [
            (
                "count above what the size needs",
                manifest(B as u32, 2, 10, &none),
            ),
            (
                "size shrunk at the same count",
                manifest(B as u32, 2, B, &none),
            ),
            (
                "count below what the size needs",
                manifest(B as u32, 1, B + 1, &none),
            ),
            (
                "another block size",
                manifest(B as u32 / 2, 2, B + 1, &none),
            ),
            ("no blocks", manifest(B as u32, 0, 0, &none)),
            (
                "a signer on an unsigned family",
                manifest(B as u32, 1, 5, &[1; 81]),
            ),
            (
                "trailing bytes",
                manifest(B as u32, 1, 5, &[SIGNER_NONE, 0]),
            ),
            ("no signer byte", manifest(B as u32, 1, 5, &[])),
            ("too short for its fields", vec![0; MANIFEST_FIXED_LEN - 1]),
        ] {
            assert!(
                open(&CHAT_MEDIA_BLOCKS, &header, &plaintext).is_err(),
                "{why}"
            );
        }
        let header = drive_header();
        let mut signed = vec![SIGNER_DRIVE_SIGNING_KEY];
        signed.extend_from_slice(&[3; ACCOUNT_LEN + SIGNATURE_LEN]);
        assert!(open(&DRIVE_BLOCKS, &header, &manifest(B as u32, 1, 5, &signed)).is_ok());
        for (why, signer) in [
            ("no signer on a signed family", vec![SIGNER_NONE]),
            ("an unknown signer kind", [&[2][..], &signed[1..]].concat()),
            ("a short signature", signed[..signed.len() - 1].to_vec()),
            ("trailing bytes", [&signed[..], &[0]].concat()),
        ] {
            assert!(
                open(&DRIVE_BLOCKS, &header, &manifest(B as u32, 1, 5, &signer)).is_err(),
                "{why}"
            );
        }
    }

    #[test]
    fn a_manifest_other_than_the_committed_one_is_refused_before_opening() {
        let header = chat_header();
        let sealed = seal_manifest_plaintext(
            &CHAT_MEDIA_BLOCKS,
            &KEY,
            &header,
            &manifest(B as u32, 1, 5, &[SIGNER_NONE]),
            &NONCE,
        )
        .unwrap();
        let digest = manifest_digest(&sealed);
        assert!(BlockReader::open(&CHAT_MEDIA_BLOCKS, &KEY, &header, &sealed, &digest).is_ok());
        let mut other = digest;
        other[0] ^= 1;
        assert!(matches!(
            BlockReader::open(&CHAT_MEDIA_BLOCKS, &KEY, &header, &sealed, &other),
            Err(CryptoError::AuthFailed)
        ));
        // Even with a wrong key: the commitment is checked first.
        assert!(matches!(
            BlockReader::open(&CHAT_MEDIA_BLOCKS, &[8; 32], &header, &sealed, &other),
            Err(CryptoError::AuthFailed)
        ));
    }

    /// The signature covers the account the manifest names: a holder of the
    /// file key can't move your signature onto another account's name.
    #[test]
    fn the_signature_covers_the_signers_account() {
        let header = drive_header();
        let key = SigningKey::from_seed(Suite::V1, &[9; 32]);
        let mut sealer = BlockSealer::new(&DRIVE_BLOCKS, &KEY, &header, 5).unwrap();
        sealer.seal_next(&[1; 5]).unwrap();
        let tail = sealer.finish(Some((&key, [3; ACCOUNT_LEN]))).unwrap();
        let sealed = &tail.bytes[..tail.bytes.len() - TRAILER_LEN];
        let honest =
            BlockReader::open(&DRIVE_BLOCKS, &KEY, &header, sealed, &tail.manifest_sha256).unwrap();
        honest
            .manifest()
            .verify_signer(&key.verifying_key())
            .unwrap();

        let signature = honest.manifest().signer.as_ref().unwrap().signature;
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&(BLOCK_SIZE as u32).to_be_bytes());
        plaintext.extend_from_slice(&1u32.to_be_bytes());
        plaintext.extend_from_slice(&5u64.to_be_bytes());
        plaintext.extend_from_slice(&honest.manifest().hashes[0]);
        plaintext.push(SIGNER_DRIVE_SIGNING_KEY);
        plaintext.extend_from_slice(&[4; ACCOUNT_LEN]);
        plaintext.extend_from_slice(&signature);
        let renamed =
            seal_manifest_plaintext(&DRIVE_BLOCKS, &KEY, &header, &plaintext, &NONCE).unwrap();
        let reader = BlockReader::open(
            &DRIVE_BLOCKS,
            &KEY,
            &header,
            &renamed,
            &manifest_digest(&renamed),
        )
        .unwrap();
        assert_eq!(
            reader.manifest().signer.as_ref().unwrap().account_id,
            [4; ACCOUNT_LEN]
        );
        assert!(reader
            .manifest()
            .verify_signer(&key.verifying_key())
            .is_err());
    }
}
