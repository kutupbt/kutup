//! The Photos library record (docs/plans/photos.md): an account's own marks
//! on photos — favourites, archived, hidden — as one account-private envelope.
//!
//! The key is a typed subkey of the recoverable master key (as the Chat
//! attachment ledger's), so nothing else is stored to recover it. The fixed
//! header carries the account incarnation, a revision and the previous
//! envelope's SHA-256, which the server checks for compare-and-swap without
//! reading anything: it learns that a record exists, its size and how often
//! it changes, never which photos are marked.
//!
//! Envelope: `magic(8) suite(2) purpose(1) reserved(1) incarnation(32)
//! revision(8) previous_digest(32) nonce(24) ciphertext_len(4)`, then the
//! XChaCha20-Poly1305 ciphertext; the header is the AAD and the input of the
//! per-envelope key.

use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use dryoc::rng::copy_randombytes;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::drive_object::parse_canonical_uuid;
use crate::error::{CryptoError, Result};

const MAGIC: &[u8; 8] = b"KUTPPL1\0";
const KEY_DERIVATION_SALT: &[u8] = b"kutup/photos-library/key/v1\0";
const ACCOUNT_KEY_SALT: &[u8] = b"kutup/account-private-subkey/v1\0";
const ACCOUNT_KEY_INFO: &[u8] = b"kutup/photos-library/account-key/v1\0";
const SUITE_XCHACHA20POLY1305_V1: u16 = 1;
const PURPOSE_LIBRARY: u8 = 1;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const DIGEST_LEN: usize = 32;
pub const PHOTOS_LIBRARY_HEADER_BYTES: usize = 112;
/// Enough for 100,000 marked photos.
pub const MAX_PHOTOS_LIBRARY_PLAINTEXT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_MARKED_PHOTOS: usize = 100_000;

/// Which record, in whose account, and after which one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhotosLibraryContextV1 {
    pub account_incarnation_id: [u8; 32],
    pub revision: u64,
    pub previous_envelope_digest: [u8; DIGEST_LEN],
}

fn parse_lower_hex_32(value: &str, field: &str) -> Result<[u8; 32]> {
    let decoded = hex::decode(value)
        .map_err(|_| CryptoError::InvalidInput(format!("{field} must be lowercase hex")))?;
    if decoded.len() != 32 || hex::encode(&decoded) != value {
        return Err(CryptoError::InvalidInput(format!(
            "{field} must be canonical 32-byte lowercase hex"
        )));
    }
    decoded
        .try_into()
        .map_err(|_| CryptoError::InvalidInput(format!("{field} length is invalid")))
}

impl PhotosLibraryContextV1 {
    /// Revision 1 has no predecessor; every later one names it.
    pub fn new(
        account_incarnation_id: &str,
        revision: u64,
        previous_envelope_digest: Option<&str>,
    ) -> Result<Self> {
        let previous_envelope_digest = match previous_envelope_digest {
            None if revision == 1 => [0u8; DIGEST_LEN],
            Some(value) if revision > 1 => {
                let digest = parse_lower_hex_32(value, "Photos library predecessor")?;
                if digest == [0u8; DIGEST_LEN] {
                    return Err(CryptoError::InvalidInput(
                        "Photos library predecessor must be non-zero".into(),
                    ));
                }
                digest
            }
            _ => {
                return Err(CryptoError::InvalidInput(
                    "Photos library revision and predecessor do not match".into(),
                ))
            }
        };
        Ok(Self {
            account_incarnation_id: parse_lower_hex_32(
                account_incarnation_id,
                "Photos library account incarnation",
            )?,
            revision,
            previous_envelope_digest,
        })
    }
}

/// The account-private key of the record, from the master key.
pub fn derive_photos_library_key(master_key: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if master_key.len() != KEY_LEN {
        return Err(CryptoError::InvalidLength {
            expected: KEY_LEN,
            got: master_key.len(),
        });
    }
    let hkdf = Hkdf::<Sha256>::new(Some(ACCOUNT_KEY_SALT), master_key);
    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    hkdf.expand(ACCOUNT_KEY_INFO, key.as_mut_slice())
        .map_err(|_| CryptoError::Backend("Photos library account HKDF expand".into()))?;
    Ok(key)
}

fn build_header(
    context: PhotosLibraryContextV1,
    nonce: &[u8; NONCE_LEN],
    ciphertext_len: u32,
) -> [u8; PHOTOS_LIBRARY_HEADER_BYTES] {
    let mut header = [0u8; PHOTOS_LIBRARY_HEADER_BYTES];
    header[..8].copy_from_slice(MAGIC);
    header[8..10].copy_from_slice(&SUITE_XCHACHA20POLY1305_V1.to_be_bytes());
    header[10] = PURPOSE_LIBRARY;
    header[12..44].copy_from_slice(&context.account_incarnation_id);
    header[44..52].copy_from_slice(&context.revision.to_be_bytes());
    header[52..84].copy_from_slice(&context.previous_envelope_digest);
    header[84..108].copy_from_slice(nonce);
    header[108..112].copy_from_slice(&ciphertext_len.to_be_bytes());
    header
}

fn derive_key(
    library_key: &[u8],
    header: &[u8; PHOTOS_LIBRARY_HEADER_BYTES],
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if library_key.len() != KEY_LEN {
        return Err(CryptoError::InvalidLength {
            expected: KEY_LEN,
            got: library_key.len(),
        });
    }
    let hkdf = Hkdf::<Sha256>::new(Some(KEY_DERIVATION_SALT), library_key);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(header, key.as_mut_slice())
        .map_err(|_| CryptoError::Backend("Photos library HKDF expand".into()))?;
    Ok(key)
}

pub fn seal(
    plaintext: &[u8],
    library_key: &[u8],
    context: PhotosLibraryContextV1,
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    copy_randombytes(&mut nonce);
    seal_with_nonce(plaintext, library_key, context, &nonce)
}

/// Deterministic-nonce entry point for canonical vectors only.
pub fn seal_with_nonce(
    plaintext: &[u8],
    library_key: &[u8],
    context: PhotosLibraryContextV1,
    nonce: &[u8],
) -> Result<Vec<u8>> {
    if plaintext.is_empty() || plaintext.len() > MAX_PHOTOS_LIBRARY_PLAINTEXT_BYTES {
        return Err(CryptoError::InvalidInput(
            "Photos library plaintext length is invalid".into(),
        ));
    }
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| CryptoError::InvalidLength {
        expected: NONCE_LEN,
        got: nonce.len(),
    })?;
    let ciphertext_len = u32::try_from(plaintext.len() + TAG_LEN)
        .map_err(|_| CryptoError::InvalidInput("Photos library plaintext is too long".into()))?;
    let header = build_header(context, &nonce, ciphertext_len);
    let key = derive_key(library_key, &header)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| CryptoError::Backend("Photos library AEAD init".into()))?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|_| CryptoError::Backend("Photos library seal".into()))?;
    let mut envelope = header.to_vec();
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

/// The public header: what the server checks.
pub fn inspect(envelope: &[u8]) -> Result<PhotosLibraryContextV1> {
    if envelope.len() < PHOTOS_LIBRARY_HEADER_BYTES + TAG_LEN + 1
        || envelope.get(..8) != Some(MAGIC)
    {
        return Err(CryptoError::TooShort);
    }
    if u16::from_be_bytes([envelope[8], envelope[9]]) != SUITE_XCHACHA20POLY1305_V1
        || envelope[10] != PURPOSE_LIBRARY
        || envelope[11] != 0
    {
        return Err(CryptoError::InvalidInput(
            "unknown Photos library suite or purpose".into(),
        ));
    }
    let revision = u64::from_be_bytes(envelope[44..52].try_into().expect("eight bytes"));
    let previous_envelope_digest: [u8; DIGEST_LEN] =
        envelope[52..84].try_into().expect("digest slice");
    if revision == 0
        || (revision == 1 && previous_envelope_digest != [0u8; DIGEST_LEN])
        || (revision > 1 && previous_envelope_digest == [0u8; DIGEST_LEN])
    {
        return Err(CryptoError::InvalidInput(
            "Photos library revision and predecessor do not match".into(),
        ));
    }
    let ciphertext_len =
        u32::from_be_bytes(envelope[108..112].try_into().expect("four bytes")) as usize;
    if !(TAG_LEN + 1..=MAX_PHOTOS_LIBRARY_PLAINTEXT_BYTES + TAG_LEN).contains(&ciphertext_len)
        || PHOTOS_LIBRARY_HEADER_BYTES.checked_add(ciphertext_len) != Some(envelope.len())
    {
        return Err(CryptoError::InvalidInput(
            "Photos library ciphertext length is invalid".into(),
        ));
    }
    Ok(PhotosLibraryContextV1 {
        account_incarnation_id: envelope[12..44].try_into().expect("incarnation slice"),
        revision,
        previous_envelope_digest,
    })
}

/// SHA-256 of a well-formed envelope, lowercase hex: the next one's predecessor.
pub fn envelope_digest(envelope: &[u8]) -> Result<String> {
    inspect(envelope)?;
    Ok(hex::encode(Sha256::digest(envelope)))
}

pub fn open(
    envelope: &[u8],
    library_key: &[u8],
    expected: PhotosLibraryContextV1,
) -> Result<Vec<u8>> {
    if inspect(envelope)? != expected {
        return Err(CryptoError::AuthFailed);
    }
    let header: &[u8; PHOTOS_LIBRARY_HEADER_BYTES] = envelope[..PHOTOS_LIBRARY_HEADER_BYTES]
        .try_into()
        .expect("fixed header");
    let key = derive_key(library_key, header)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| CryptoError::Backend("Photos library AEAD init".into()))?;
    cipher
        .decrypt(
            XNonce::from_slice(&envelope[84..108]),
            Payload {
                msg: &envelope[PHOTOS_LIBRARY_HEADER_BYTES..],
                aad: header,
            },
        )
        .map_err(|_| CryptoError::AuthFailed)
}

pub fn decode_canonical_b64(value: &str) -> Result<Vec<u8>> {
    let decoded = base64::engine::general_purpose::STANDARD.decode(value)?;
    if base64::engine::general_purpose::STANDARD.encode(&decoded) != value {
        return Err(CryptoError::InvalidInput(
            "Photos library envelope must use canonical base64".into(),
        ));
    }
    Ok(decoded)
}

/// What the record holds: file ids, each set sorted and without repeats.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhotosLibraryV1 {
    pub favourites: Vec<String>,
    pub archived: Vec<String>,
    pub hidden: Vec<String>,
}

impl PhotosLibraryV1 {
    pub fn validate(&self) -> Result<()> {
        let total = self.favourites.len() + self.archived.len() + self.hidden.len();
        if total > MAX_MARKED_PHOTOS {
            return Err(CryptoError::InvalidInput(
                "Photos library marks too many photos".into(),
            ));
        }
        for set in [&self.favourites, &self.archived, &self.hidden] {
            for (i, id) in set.iter().enumerate() {
                parse_canonical_uuid(id, "Photos library file")?;
                if i > 0 && set[i - 1] >= *id {
                    return Err(CryptoError::InvalidInput(
                        "Photos library sets must be sorted without repeats".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Sorted, deduplicated, checked: the canonical form of any input.
    pub fn canonicalize(mut self) -> Result<Self> {
        for set in [&mut self.favourites, &mut self.archived, &mut self.hidden] {
            set.sort();
            set.dedup();
        }
        self.validate()?;
        Ok(self)
    }
}

pub fn encode_library(library: &PhotosLibraryV1) -> Result<Vec<u8>> {
    library.validate()?;
    serde_json::to_vec(library).map_err(|_| CryptoError::InvalidInput("encode library".into()))
}

pub fn decode_library(bytes: &[u8]) -> Result<PhotosLibraryV1> {
    let library: PhotosLibraryV1 = serde_json::from_slice(bytes)
        .map_err(|_| CryptoError::InvalidInput("Photos library is not valid".into()))?;
    library.validate()?;
    Ok(library)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INCARNATION: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const A: &str = "22222222-2222-4222-8222-222222222222";
    const B: &str = "33333333-3333-4333-8333-333333333333";

    fn library() -> PhotosLibraryV1 {
        PhotosLibraryV1 {
            favourites: vec![B.into(), A.into(), A.into()],
            archived: vec![],
            hidden: vec![B.into()],
        }
        .canonicalize()
        .unwrap()
    }

    #[test]
    fn seals_and_opens_a_chain_of_revisions() {
        let key = derive_photos_library_key(&[9u8; 32]).unwrap();
        let first_context = PhotosLibraryContextV1::new(INCARNATION, 1, None).unwrap();
        let first = seal(
            &encode_library(&library()).unwrap(),
            key.as_slice(),
            first_context,
        )
        .unwrap();
        assert_eq!(inspect(&first).unwrap(), first_context);
        let opened = open(&first, key.as_slice(), first_context).unwrap();
        assert_eq!(decode_library(&opened).unwrap(), library());

        let digest = envelope_digest(&first).unwrap();
        let second_context = PhotosLibraryContextV1::new(INCARNATION, 2, Some(&digest)).unwrap();
        let second = seal(
            b"{\"favourites\":[],\"archived\":[],\"hidden\":[]}",
            key.as_slice(),
            second_context,
        )
        .unwrap();
        assert_eq!(
            inspect(&second).unwrap().previous_envelope_digest.to_vec(),
            hex::decode(&digest).unwrap()
        );
        // Opened only as what it claims to be.
        assert!(open(&second, key.as_slice(), first_context).is_err());
        let other = derive_photos_library_key(&[8u8; 32]).unwrap();
        assert!(open(&first, other.as_slice(), first_context).is_err());
        let mut tampered = first.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(open(&tampered, key.as_slice(), first_context).is_err());
    }

    #[test]
    fn contexts_follow_the_chain_rules() {
        assert!(PhotosLibraryContextV1::new(INCARNATION, 0, None).is_err());
        assert!(PhotosLibraryContextV1::new(INCARNATION, 2, None).is_err());
        assert!(PhotosLibraryContextV1::new(INCARNATION, 1, Some(INCARNATION)).is_err());
        assert!(PhotosLibraryContextV1::new(INCARNATION, 2, Some(&"00".repeat(32))).is_err());
        assert!(PhotosLibraryContextV1::new("AB", 1, None).is_err());
    }

    #[test]
    fn the_record_is_canonical() {
        assert_eq!(
            std::str::from_utf8(&encode_library(&library()).unwrap()).unwrap(),
            format!(r#"{{"favourites":["{A}","{B}"],"archived":[],"hidden":["{B}"]}}"#)
        );
        for bad in [
            format!(r#"{{"favourites":["{B}","{A}"],"archived":[],"hidden":[]}}"#),
            format!(r#"{{"favourites":["{A}","{A}"],"archived":[],"hidden":[]}}"#),
            r#"{"favourites":["x"],"archived":[],"hidden":[]}"#.to_string(),
            r#"{"favourites":[],"archived":[]}"#.to_string(),
            r#"{"favourites":[],"archived":[],"hidden":[],"albums":[]}"#.to_string(),
        ] {
            assert!(decode_library(bad.as_bytes()).is_err(), "{bad}");
        }
    }
}
