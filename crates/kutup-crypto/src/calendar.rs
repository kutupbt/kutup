//! Calendars (docs/plans/calendar.md, E1): Proton Calendar's keys and
//! packets, through rPGP as Mail's address keys.
//!
//! - Each calendar has its own OpenPGP key, in the address keys' shape, its
//!   secret locked with a passphrase (`generateCalendarKey`; user ID
//!   "Calendar key", so an exported key confuses no one).
//! - The passphrase is the base64 text of 32 random bytes. It is kept as one
//!   data packet under a session key, one key packet per member (to that
//!   member's address key) and the owner's detached signature over it
//!   (Proton's `encryptPassphrase`), so adding a member re-wraps the session
//!   key and re-encrypts nothing.
//! - Events and the calendar's encrypted metadata are data packets under
//!   session keys wrapped to the calendar key, each part signed (detached)
//!   by its author's address key ([`crate::calendar_event`]).
//!
//! Only version 3 key packets and SEIPDv1 data packets (AES-256) are made or
//! read: what the address keys and every OpenPGP client use.

use std::io::{BufReader, Read as _};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use pgp::{
    composed::{
        Deserializable, Message, MessageBuilder, PlainSessionKey, SignedPublicKey, SignedSecretKey,
    },
    crypto::sym::SymmetricKeyAlgorithm,
    packet::{Packet, PacketParser, PublicKeyEncryptedSessionKey},
    ser::Serialize as _,
    types::{DecryptionKey as _, EskType, KeyDetails as _, Password},
};
use rand::RngCore as _;
use zeroize::Zeroizing;

use crate::calendar_event::{CalendarEncrypted, CalendarSigned, SharedEncrypted, SharedSigned};
use crate::error::{CryptoError, Result};
use crate::mail_key::{
    backend, encryption_subkey, fingerprint_of, generate_key, packet_extent, parse_recipient,
    sign_detached, verify_detached, FINGERPRINT_LEN,
};

/// The calendar key's user ID, as Proton's.
pub const CALENDAR_KEY_USER_ID: &str = "Calendar key";
/// Random bytes in a calendar's passphrase (its text is their base64).
pub const PASSPHRASE_BYTES: usize = 32;
/// An AES-256 session key.
pub const SESSION_KEY_LEN: usize = 32;
/// The largest data packet read: an event part or metadata is far smaller.
pub const MAX_DATA_PACKET_LEN: usize = 256 * 1024;
const MAX_KEY_PACKET_LEN: usize = 1024;
const MAX_LOCKED_KEY_LEN: usize = 8 * 1024;
const TAG_PKESK: u8 = 1;
const TAG_SEIPD: u8 = 18;

/// A session key: the AES-256 key of one data packet.
pub struct SessionKey(Zeroizing<[u8; SESSION_KEY_LEN]>);

impl SessionKey {
    /// A fresh random session key.
    pub fn generate() -> Self {
        let mut key = Zeroizing::new([0u8; SESSION_KEY_LEN]);
        rand::rngs::OsRng.fill_bytes(key.as_mut());
        SessionKey(key)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let key: [u8; SESSION_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidInput("a session key is 32 bytes".into()))?;
        Ok(SessionKey(Zeroizing::new(key)))
    }

    pub fn as_bytes(&self) -> &[u8; SESSION_KEY_LEN] {
        &self.0
    }

    fn plain(&self) -> PlainSessionKey {
        PlainSessionKey::V3_4 {
            sym_alg: SymmetricKeyAlgorithm::AES256,
            key: self.0.to_vec().into(),
        }
    }
}

/// A calendar's passphrase: the base64 text of 32 random bytes, as Proton's
/// `generatePassphrase`. It locks the calendar key.
pub struct Passphrase(Zeroizing<String>);

impl Passphrase {
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; PASSPHRASE_BYTES]);
        rand::rngs::OsRng.fill_bytes(bytes.as_mut());
        Passphrase(Zeroizing::new(STANDARD.encode(bytes.as_ref())))
    }

    /// A passphrase as decrypted: exactly the base64 of 32 bytes.
    pub fn from_text(text: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(text)
            .map_err(|_| CryptoError::InvalidInput("passphrase is not text".into()))?;
        let bytes = Zeroizing::new(
            STANDARD
                .decode(text)
                .map_err(|_| CryptoError::InvalidInput("passphrase is not base64".into()))?,
        );
        if bytes.len() != PASSPHRASE_BYTES {
            return Err(CryptoError::InvalidInput(
                "a passphrase is 32 random bytes".into(),
            ));
        }
        Ok(Passphrase(Zeroizing::new(text.to_owned())))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A new calendar key.
pub struct CalendarKey {
    /// The binary OpenPGP public key.
    pub public_key: Vec<u8>,
    /// The binary OpenPGP secret key, every secret part locked with the
    /// passphrase (OpenPGP's iterated and salted S2K, AES-256).
    pub locked_secret_key: Vec<u8>,
    pub fingerprint: [u8; FINGERPRINT_LEN],
    /// The key as made, to seal the new calendar's name with.
    pub unlocked: UnlockedCalendarKey,
}

/// A calendar's key, unlocked: its secret and the public key derived from
/// that secret, never one a server handed over. Everything sealed to the
/// calendar goes through it, so a server can't make a client encrypt to a
/// key of its own (the public key on the server's row is only for the
/// server's own checks).
pub struct UnlockedCalendarKey {
    secret: Zeroizing<Vec<u8>>,
    public: Vec<u8>,
    fingerprint: [u8; FINGERPRINT_LEN],
}

impl UnlockedCalendarKey {
    fn from_secret(secret: Zeroizing<Vec<u8>>) -> Result<Self> {
        let key = SignedSecretKey::from_bytes(secret.as_slice())
            .map_err(|_| CryptoError::InvalidInput("calendar key does not parse".into()))?;
        let public = SignedPublicKey::from(key);
        Ok(UnlockedCalendarKey {
            fingerprint: fingerprint_of(&public)?,
            public: public.to_bytes().map_err(backend)?,
            secret,
        })
    }

    /// The public key, derived from the secret.
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    pub fn fingerprint(&self) -> [u8; FINGERPRINT_LEN] {
        self.fingerprint
    }

    /// Seals an event for this calendar, signed by its author's unlocked
    /// address key. Fresh session keys, unless kept from an earlier version
    /// (invitations keep the shared one, E4).
    pub fn seal_event(
        &self,
        parts: &EventParts,
        author_secret_key: &[u8],
        shared_key: Option<&SessionKey>,
        calendar_key: Option<&SessionKey>,
    ) -> Result<SealedEvent> {
        seal_event_to(
            parts,
            &self.public,
            author_secret_key,
            shared_key,
            calendar_key,
        )
    }

    /// Opens an event, checking every part's signature against the author's
    /// address keys.
    pub fn open_event(
        &self,
        event: &SealedEvent,
        author_public_keys: &[&[u8]],
    ) -> Result<OpenedEvent> {
        open_event_with(event, &self.secret, author_public_keys)
    }

    /// Seals this calendar's name and description, bound to its id and key.
    pub fn seal_metadata(
        &self,
        calendar_id: &str,
        name: &str,
        description: &str,
        author_secret_key: &[u8],
    ) -> Result<SealedMetadata> {
        let metadata = CalendarMetadataV1 {
            version: 1,
            calendar_id: calendar_id.to_owned(),
            fingerprint: hex::encode(self.fingerprint),
            name: name.to_owned(),
            description: description.to_owned(),
        };
        seal_metadata_to(&metadata, &self.public, author_secret_key)
    }

    /// Opens this calendar's name and description. Refused unless they name
    /// `calendar_id` and this key (a server can't serve one calendar's name
    /// under another's id); `verified` says whether one of the given address
    /// keys (the owner's) signed them.
    pub fn open_metadata(
        &self,
        sealed: &SealedMetadata,
        calendar_id: &str,
        author_public_keys: &[&[u8]],
    ) -> Result<(CalendarMetadataV1, bool)> {
        let (metadata, verified) = open_metadata_with(sealed, &self.secret, author_public_keys)?;
        if metadata.calendar_id != calendar_id
            || metadata.fingerprint != hex::encode(self.fingerprint)
        {
            return Err(CryptoError::InvalidInput(
                "the name and description are another calendar's".into(),
            ));
        }
        Ok((metadata, verified))
    }

    /// Opens a key packet to this calendar's key.
    pub fn open_key_packet(&self, key_packet: &[u8]) -> Result<SessionKey> {
        open_key_packet(key_packet, &self.secret)
    }

    /// The unlocked secret, for opening key packets in this crate's tests.
    #[cfg(test)]
    pub(crate) fn secret(&self) -> &[u8] {
        &self.secret
    }
}

/// The cost a calendar key's S2K may have: OpenPGP's iterated count byte as
/// this crate writes it (rPGP's v4 default, 224), and no other S2K. The
/// passphrase is 32 random bytes, so the S2K adds nothing to its strength;
/// the rule only keeps a server from making clients do arbitrary work.
const MAX_S2K_COUNT: u8 = 224;

/// Whether every secret part of `key` is locked the way this crate locks
/// a calendar key: CFB with AES-256 over an iterated and salted S2K of at
/// most [`MAX_S2K_COUNT`] (no Argon2 a server could size).
fn locked_as_written(key: &SignedSecretKey) -> bool {
    use pgp::types::{S2kParams, SecretParams, StringToKey};
    let ok = |params: &SecretParams| match params {
        SecretParams::Encrypted(encrypted) => matches!(
            encrypted.string_to_key_params(),
            S2kParams::Cfb {
                sym_alg: SymmetricKeyAlgorithm::AES256,
                s2k: StringToKey::IteratedAndSalted { count, .. },
                ..
            } if *count <= MAX_S2K_COUNT
        ),
        SecretParams::Plain(_) => false,
    };
    ok(key.primary_key.secret_params())
        && key
            .secret_subkeys
            .iter()
            .all(|subkey| ok(subkey.key.secret_params()))
}

/// Generates a calendar key locked with `passphrase`, created at
/// `created_at_secs` (Unix seconds).
pub fn generate_calendar_key(passphrase: &Passphrase, created_at_secs: u32) -> Result<CalendarKey> {
    let generated = generate_key(CALENDAR_KEY_USER_ID.to_owned(), created_at_secs)?;
    let mut key = SignedSecretKey::from_bytes(generated.secret_key.as_slice()).map_err(backend)?;
    let password = Password::from(passphrase.as_str());
    key.primary_key
        .set_password(rand::rngs::OsRng, &password)
        .map_err(backend)?;
    for subkey in &mut key.secret_subkeys {
        subkey
            .key
            .set_password(rand::rngs::OsRng, &password)
            .map_err(backend)?;
    }
    Ok(CalendarKey {
        public_key: generated.public_key,
        locked_secret_key: key.to_bytes().map_err(backend)?,
        fingerprint: generated.fingerprint,
        unlocked: UnlockedCalendarKey::from_secret(generated.secret_key)?,
    })
}

/// Checks a calendar's public key as a server stores it: one key in the
/// calendar keys' shape. Returns its fingerprint.
pub fn inspect_calendar_public_key(public_key: &[u8]) -> Result<[u8; FINGERPRINT_LEN]> {
    let key = SignedPublicKey::from_bytes(public_key)
        .map_err(|_| CryptoError::InvalidInput("calendar key does not parse".into()))?;
    key.verify_bindings()
        .map_err(|_| CryptoError::InvalidInput("calendar key does not verify".into()))?;
    let user_ids: Vec<_> = key.details.users.iter().map(|user| user.id.id()).collect();
    if user_ids != [CALENDAR_KEY_USER_ID.as_bytes()] || key.public_subkeys.len() != 1 {
        return Err(CryptoError::InvalidInput(
            "not a calendar key: one user ID \"Calendar key\" and one encryption subkey".into(),
        ));
    }
    encryption_subkey(&key)?;
    fingerprint_of(&key)
}

/// Checks a locked calendar secret key as a server stores it: it parses,
/// and it is the secret of `public_key` (the same primary and subkey). The
/// server can't unlock it; a member who can checks the rest.
pub fn inspect_locked_calendar_key(locked_secret_key: &[u8], public_key: &[u8]) -> Result<()> {
    if locked_secret_key.len() > MAX_LOCKED_KEY_LEN {
        return Err(CryptoError::InvalidInput(
            "calendar key is too large".into(),
        ));
    }
    let secret = SignedSecretKey::from_bytes(locked_secret_key)
        .map_err(|_| CryptoError::InvalidInput("calendar secret key does not parse".into()))?;
    let public = SignedPublicKey::from_bytes(public_key)
        .map_err(|_| CryptoError::InvalidInput("calendar key does not parse".into()))?;
    let derived = SignedPublicKey::from(secret.clone());
    let same_subkeys = derived.public_subkeys.len() == public.public_subkeys.len()
        && derived
            .public_subkeys
            .iter()
            .zip(&public.public_subkeys)
            .all(|(a, b)| a.key.fingerprint() == b.key.fingerprint());
    if derived.fingerprint() != public.fingerprint() || !same_subkeys {
        return Err(CryptoError::InvalidInput(
            "the secret key is not the calendar key's".into(),
        ));
    }
    if !locked_as_written(&secret) {
        return Err(CryptoError::InvalidInput(
            "a calendar's secret key is locked with its passphrase (AES-256, iterated S2K)".into(),
        ));
    }
    Ok(())
}

/// Checks a sealed event's packets as a server can: both key packets are to
/// the calendar key, and each encrypted part is one data packet. (Only a
/// member can open them.)
pub fn check_sealed_shape(event: &SealedEvent, calendar_public_key: &[u8]) -> Result<()> {
    let calendar = encryption_key_id(calendar_public_key)?;
    for packet in [&event.shared_key_packet, &event.calendar_key_packet] {
        if key_packet_key_id(packet)? != calendar {
            return Err(CryptoError::InvalidInput(
                "a key packet is not to the calendar key".into(),
            ));
        }
    }
    let encrypted =
        std::iter::once(&event.shared_encrypted).chain(event.calendar_encrypted.as_ref());
    for part in encrypted {
        let (tag, _, length) = packet_extent(&part.data)?;
        if tag != TAG_SEIPD || length != part.data.len() || part.data.len() > MAX_DATA_PACKET_LEN {
            return Err(CryptoError::InvalidInput(
                "an encrypted part is one data packet".into(),
            ));
        }
    }
    Ok(())
}

/// Unlocks a calendar's secret key with its passphrase. Refused before any
/// work when the key isn't locked as this crate locks one (a server can't
/// pick the S2K's cost); a wrong passphrase is [`CryptoError::AuthFailed`].
pub fn unlock_calendar_key(
    locked_secret_key: &[u8],
    passphrase: &Passphrase,
) -> Result<UnlockedCalendarKey> {
    if locked_secret_key.len() > MAX_LOCKED_KEY_LEN {
        return Err(CryptoError::InvalidInput(
            "calendar key is too large".into(),
        ));
    }
    let mut key = SignedSecretKey::from_bytes(locked_secret_key)
        .map_err(|_| CryptoError::InvalidInput("calendar key does not parse".into()))?;
    if !locked_as_written(&key) {
        return Err(CryptoError::InvalidInput(
            "the calendar key is not locked as Kutup locks one".into(),
        ));
    }
    let password = Password::from(passphrase.as_str());
    key.primary_key
        .remove_password(&password)
        .map_err(|_| CryptoError::AuthFailed)?;
    for subkey in &mut key.secret_subkeys {
        subkey
            .key
            .remove_password(&password)
            .map_err(|_| CryptoError::AuthFailed)?;
    }
    UnlockedCalendarKey::from_secret(key.to_bytes().map(Zeroizing::new).map_err(backend)?)
}

/// A key packet carrying `session_key` to `public_key`'s encryption subkey
/// (version 3, as the address keys use): a member's copy of a calendar's
/// passphrase, or an event's key packet to its calendar.
pub(crate) fn key_packet_to(session_key: &SessionKey, public_key: &[u8]) -> Result<Vec<u8>> {
    let recipient = parse_recipient(public_key)?;
    let subkey = encryption_subkey(&recipient)?;
    let raw = session_key.0.to_vec().into();
    let pkesk = PublicKeyEncryptedSessionKey::from_session_key_v3(
        rand::rngs::OsRng,
        &raw,
        SymmetricKeyAlgorithm::AES256,
        subkey,
    )
    .map_err(backend)?;
    Packet::PublicKeyEncryptedSessionKey(pkesk)
        .to_bytes()
        .map_err(backend)
}

/// Opens a key packet with an unlocked secret key (an address key, or a
/// calendar key from [`unlock_calendar_key`]): the session key, which must
/// be AES-256. A key packet for another key, or one that doesn't open, is
/// [`CryptoError::AuthFailed`].
pub fn open_key_packet(key_packet: &[u8], secret_key: &[u8]) -> Result<SessionKey> {
    if key_packet.len() > MAX_KEY_PACKET_LEN {
        return Err(CryptoError::InvalidInput("key packet is too large".into()));
    }
    let mut packets = PacketParser::new(BufReader::new(key_packet));
    let pkesk = match (packets.next(), packets.next()) {
        (Some(Ok(Packet::PublicKeyEncryptedSessionKey(pkesk))), None) => pkesk,
        _ => return Err(CryptoError::InvalidInput("not a single key packet".into())),
    };
    let key = SignedSecretKey::from_bytes(secret_key)
        .map_err(|_| CryptoError::InvalidInput("secret key does not parse".into()))?;
    let values = pkesk.values().map_err(backend)?;
    let subkey = key
        .secret_subkeys
        .iter()
        .find(|subkey| pkesk.match_identity(&subkey.key))
        .ok_or(CryptoError::AuthFailed)?;
    let plain = subkey
        .key
        .decrypt(&Password::empty(), values, EskType::V3_4)
        .map_err(|_| CryptoError::AuthFailed)?
        .map_err(|_| CryptoError::AuthFailed)?;
    match &plain {
        PlainSessionKey::V3_4 {
            sym_alg: SymmetricKeyAlgorithm::AES256,
            key,
        } => SessionKey::from_bytes(key.as_ref()),
        _ => Err(CryptoError::InvalidInput(
            "the session key is not AES-256".into(),
        )),
    }
}

/// A data packet: `plaintext` as a binary literal, encrypted with
/// `session_key` (SEIPDv1, AES-256), and nothing else.
pub(crate) fn encrypt_data_packet(session_key: &SessionKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut builder = MessageBuilder::from_bytes("", plaintext.to_vec())
        .seipd_v1(rand::rngs::OsRng, SymmetricKeyAlgorithm::AES256);
    builder
        .set_session_key(session_key.0.to_vec().into())
        .map_err(backend)?;
    let packet = builder.to_vec(rand::rngs::OsRng).map_err(backend)?;
    let (tag, _, length) = packet_extent(&packet)?;
    if tag != TAG_SEIPD || length != packet.len() {
        return Err(CryptoError::Backend("expected one data packet".into()));
    }
    Ok(packet)
}

/// Decrypts a data packet made by [`encrypt_data_packet`] (or Proton's):
/// exactly one SEIPDv1 packet holding a literal, nothing compressed or
/// signed inside. A wrong key is [`CryptoError::AuthFailed`].
pub fn decrypt_data_packet(
    session_key: &SessionKey,
    data_packet: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if data_packet.len() > MAX_DATA_PACKET_LEN {
        return Err(CryptoError::InvalidInput("data packet is too large".into()));
    }
    let (tag, _, length) = packet_extent(data_packet)?;
    if tag != TAG_SEIPD || length != data_packet.len() {
        return Err(CryptoError::InvalidInput("not a single data packet".into()));
    }
    let message = Message::from_bytes(data_packet)
        .map_err(|_| CryptoError::InvalidInput("data packet does not parse".into()))?;
    let mut message = message
        .decrypt_with_session_key(session_key.plain())
        .map_err(|_| CryptoError::AuthFailed)?;
    if !message.is_literal() {
        return Err(CryptoError::InvalidInput(
            "a data packet holds one literal".into(),
        ));
    }
    let mut data = Zeroizing::new(Vec::new());
    message
        .read_to_end(&mut data)
        .map_err(|_| CryptoError::AuthFailed)?;
    if data.len() > MAX_DATA_PACKET_LEN {
        return Err(CryptoError::InvalidInput("data is too large".into()));
    }
    Ok(data)
}

/// A calendar's passphrase as stored: one data packet, the owner's detached
/// signature over the passphrase, and one key packet per member, in the
/// order of the member keys given.
pub struct SealedPassphrase {
    pub data_packet: Vec<u8>,
    /// Armored, as Proton's.
    pub signature: String,
    pub key_packets: Vec<Vec<u8>>,
}

/// Seals a new calendar's `passphrase` for its owner, signed by the owner's
/// unlocked address key: the one key packet is to the public key derived
/// from that secret, never to one a server hands over (#307 review N1).
pub fn seal_passphrase(
    passphrase: &Passphrase,
    owner_secret_key: &[u8],
) -> Result<SealedPassphrase> {
    let owner = SignedSecretKey::from_bytes(owner_secret_key)
        .map_err(|_| CryptoError::InvalidInput("secret key does not parse".into()))?;
    let owner_public = SignedPublicKey::from(owner).to_bytes().map_err(backend)?;
    seal_passphrase_to(passphrase, &[&owner_public], owner_secret_key)
}

/// Seals `passphrase` for `member_public_keys` (each member's primary
/// address key, verified by the caller), signed by the owner's unlocked
/// address key. Sharing (E3) adds members through it.
pub(crate) fn seal_passphrase_to(
    passphrase: &Passphrase,
    member_public_keys: &[&[u8]],
    owner_secret_key: &[u8],
) -> Result<SealedPassphrase> {
    if member_public_keys.is_empty() {
        return Err(CryptoError::InvalidInput("a calendar has a member".into()));
    }
    let session_key = SessionKey::generate();
    Ok(SealedPassphrase {
        data_packet: encrypt_data_packet(&session_key, passphrase.as_str().as_bytes())?,
        signature: sign_detached(owner_secret_key, passphrase.as_str().as_bytes())?,
        key_packets: member_public_keys
            .iter()
            .map(|key| key_packet_to(&session_key, key))
            .collect::<Result<_>>()?,
    })
}

/// Opens a member's copy of a calendar's passphrase with the member's
/// unlocked address key, and checks the signature against the owner's
/// address keys (any of them). An unsigned or wrongly signed passphrase is
/// refused: a server must not hand a member a passphrase of its own.
pub fn open_passphrase(
    key_packet: &[u8],
    data_packet: &[u8],
    signature: &[u8],
    member_secret_key: &[u8],
    owner_public_keys: &[&[u8]],
) -> Result<Passphrase> {
    let session_key = open_key_packet(key_packet, member_secret_key)?;
    let text = decrypt_data_packet(&session_key, data_packet)?;
    let passphrase = Passphrase::from_text(&text)?;
    let signed = owner_public_keys.iter().any(|key| {
        verify_detached(signature, passphrase.as_str().as_bytes(), key).unwrap_or(false)
    });
    if !signed {
        return Err(CryptoError::AuthFailed);
    }
    Ok(passphrase)
}

/// The key ID a key packet is encrypted to (a server checks that an event's
/// key packets name the calendar key, and a member's names their address
/// key).
pub fn key_packet_key_id(key_packet: &[u8]) -> Result<[u8; 8]> {
    let (tag, _, length) = packet_extent(key_packet)?;
    if tag != TAG_PKESK || length != key_packet.len() {
        return Err(CryptoError::InvalidInput("not a single key packet".into()));
    }
    crate::mail_key::key_packet_key_id(key_packet)
}

/// A public key's encryption subkey's key ID, to compare with
/// [`key_packet_key_id`].
pub fn encryption_key_id(public_key: &[u8]) -> Result<[u8; 8]> {
    let key = parse_recipient(public_key)?;
    let subkey = encryption_subkey(&key)?;
    Ok(subkey
        .legacy_key_id()
        .as_ref()
        .try_into()
        .expect("eight bytes"))
}

/// One part of an event, as stored: a signed part's text in the clear, an
/// encrypted part's data packet; each with its author's detached signature
/// over the part's text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventPart {
    pub data: Vec<u8>,
    /// Armored, as Proton's.
    pub signature: String,
}

/// An event as stored (Proton's `SharedEvents`, `CalendarEvents` and the two
/// key packets).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedEvent {
    pub shared_key_packet: Vec<u8>,
    pub calendar_key_packet: Vec<u8>,
    pub shared_signed: EventPart,
    pub shared_encrypted: EventPart,
    pub calendar_signed: EventPart,
    pub calendar_encrypted: Option<EventPart>,
}

/// An event's parts, to seal.
pub struct EventParts {
    pub shared_signed: SharedSigned,
    pub shared_encrypted: SharedEncrypted,
    pub calendar_signed: CalendarSigned,
    pub calendar_encrypted: Option<CalendarEncrypted>,
}

/// Seals an event to `calendar_public_key`: only through
/// [`UnlockedCalendarKey::seal_event`], whose key is derived from the secret.
fn seal_event_to(
    parts: &EventParts,
    calendar_public_key: &[u8],
    author_secret_key: &[u8],
    shared_key: Option<&SessionKey>,
    calendar_key: Option<&SessionKey>,
) -> Result<SealedEvent> {
    check_one_uid(parts)?;
    let fresh_shared;
    let shared_key = match shared_key {
        Some(key) => key,
        None => {
            fresh_shared = SessionKey::generate();
            &fresh_shared
        }
    };
    let fresh_calendar;
    let calendar_key = match calendar_key {
        Some(key) => key,
        None => {
            fresh_calendar = SessionKey::generate();
            &fresh_calendar
        }
    };
    let signed = |text: String| -> Result<EventPart> {
        Ok(EventPart {
            signature: sign_detached(author_secret_key, text.as_bytes())?,
            data: text.into_bytes(),
        })
    };
    let sealed = |text: String, key: &SessionKey| -> Result<EventPart> {
        Ok(EventPart {
            signature: sign_detached(author_secret_key, text.as_bytes())?,
            data: encrypt_data_packet(key, text.as_bytes())?,
        })
    };
    Ok(SealedEvent {
        shared_key_packet: key_packet_to(shared_key, calendar_public_key)?,
        calendar_key_packet: key_packet_to(calendar_key, calendar_public_key)?,
        shared_signed: signed(parts.shared_signed.build()?)?,
        shared_encrypted: sealed(parts.shared_encrypted.build()?, shared_key)?,
        calendar_signed: signed(parts.calendar_signed.build()?)?,
        calendar_encrypted: parts
            .calendar_encrypted
            .as_ref()
            .map(|part| part.build().and_then(|text| sealed(text, calendar_key)))
            .transpose()?,
    })
}

fn check_one_uid(parts: &EventParts) -> Result<()> {
    let uid = &parts.shared_signed.uid;
    let same = parts.shared_encrypted.uid == *uid
        && parts.calendar_signed.uid == *uid
        && parts
            .calendar_encrypted
            .as_ref()
            .is_none_or(|part| part.uid == *uid);
    if !same {
        return Err(CryptoError::InvalidInput(
            "an event's parts name one UID".into(),
        ));
    }
    Ok(())
}

/// Checks the signed parts as a server can, before storing an event: each
/// in its canonical form and signed by one of the author's address keys.
/// Returns the shared signed part, which the server reads its columns from.
pub fn check_signed_parts(
    event: &SealedEvent,
    author_public_keys: &[&[u8]],
) -> Result<(SharedSigned, CalendarSigned)> {
    let text = |part: &EventPart| -> Result<String> {
        if !signed_by(&part.signature, &part.data, author_public_keys) {
            return Err(CryptoError::AuthFailed);
        }
        String::from_utf8(part.data.clone())
            .map_err(|_| CryptoError::InvalidInput("a signed part is text".into()))
    };
    let shared = SharedSigned::parse(&text(&event.shared_signed)?)?;
    let calendar = CalendarSigned::parse(&text(&event.calendar_signed)?)?;
    if calendar.uid != shared.uid {
        return Err(CryptoError::InvalidInput(
            "an event's parts name one UID".into(),
        ));
    }
    for packet in [&event.shared_key_packet, &event.calendar_key_packet] {
        key_packet_key_id(packet)?;
    }
    Ok((shared, calendar))
}

fn signed_by(signature: &str, data: &[u8], public_keys: &[&[u8]]) -> bool {
    public_keys
        .iter()
        .any(|key| verify_detached(signature.as_bytes(), data, key).unwrap_or(false))
}

/// An opened event: its parts, and whether each encrypted part's signature
/// is its author's (a client shows an event whose parts don't verify as
/// such, as Proton's `verificationStatus`).
pub struct OpenedEvent {
    pub parts: EventParts,
    pub verified: bool,
}

fn open_event_with(
    event: &SealedEvent,
    calendar_secret_key: &[u8],
    author_public_keys: &[&[u8]],
) -> Result<OpenedEvent> {
    let shared_key = open_key_packet(&event.shared_key_packet, calendar_secret_key)?;
    let calendar_key = open_key_packet(&event.calendar_key_packet, calendar_secret_key)?;
    let mut verified = true;
    let mut read = |part: &EventPart, key: Option<&SessionKey>| -> Result<String> {
        let data = match key {
            Some(key) => decrypt_data_packet(key, &part.data)?,
            None => Zeroizing::new(part.data.clone()),
        };
        verified &= signed_by(&part.signature, &data, author_public_keys);
        String::from_utf8(data.to_vec())
            .map_err(|_| CryptoError::InvalidInput("an event part is text".into()))
    };
    let parts = EventParts {
        shared_signed: SharedSigned::parse(&read(&event.shared_signed, None)?)?,
        shared_encrypted: SharedEncrypted::parse(&read(
            &event.shared_encrypted,
            Some(&shared_key),
        )?)?,
        calendar_signed: CalendarSigned::parse(&read(&event.calendar_signed, None)?)?,
        calendar_encrypted: event
            .calendar_encrypted
            .as_ref()
            .map(|part| {
                read(part, Some(&calendar_key)).and_then(|text| CalendarEncrypted::parse(&text))
            })
            .transpose()?,
    };
    check_one_uid(&parts)?;
    Ok(OpenedEvent { parts, verified })
}

/// A calendar's name and description (D-1: encrypted, unlike Proton's),
/// as stored: a key packet to the calendar key, a data packet with their
/// JSON, and the author's signature over it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedMetadata {
    pub key_packet: Vec<u8>,
    pub data_packet: Vec<u8>,
    pub signature: String,
}

/// A calendar's name and description.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalendarMetadataV1 {
    pub version: u16,
    /// The calendar it names, and the fingerprint (hex) of its key: signed
    /// with the name, so a server can't serve it under another calendar.
    pub calendar_id: String,
    pub fingerprint: String,
    pub name: String,
    pub description: String,
}

/// The longest name and description, in characters (Proton's).
pub const MAX_CALENDAR_NAME_CHARS: usize = 100;
pub const MAX_CALENDAR_DESCRIPTION_CHARS: usize = 255;

impl CalendarMetadataV1 {
    fn check(&self) -> Result<()> {
        if self.version != 1
            || self.calendar_id.is_empty()
            || self.calendar_id.len() > 64
            || self.fingerprint.len() != 2 * FINGERPRINT_LEN
            || self.name.trim().is_empty()
            || self.name.chars().count() > MAX_CALENDAR_NAME_CHARS
            || self.description.chars().count() > MAX_CALENDAR_DESCRIPTION_CHARS
            || self
                .name
                .chars()
                .chain(self.description.chars())
                .any(|c| c.is_control() && c != '\n')
        {
            return Err(CryptoError::InvalidInput(
                "calendar name or description is invalid".into(),
            ));
        }
        Ok(())
    }
}

fn seal_metadata_to(
    metadata: &CalendarMetadataV1,
    calendar_public_key: &[u8],
    author_secret_key: &[u8],
) -> Result<SealedMetadata> {
    metadata.check()?;
    let json = serde_json::to_vec(metadata).map_err(backend)?;
    let key = SessionKey::generate();
    Ok(SealedMetadata {
        key_packet: key_packet_to(&key, calendar_public_key)?,
        data_packet: encrypt_data_packet(&key, &json)?,
        signature: sign_detached(author_secret_key, &json)?,
    })
}

fn open_metadata_with(
    sealed: &SealedMetadata,
    calendar_secret_key: &[u8],
    author_public_keys: &[&[u8]],
) -> Result<(CalendarMetadataV1, bool)> {
    let key = open_key_packet(&sealed.key_packet, calendar_secret_key)?;
    let json = decrypt_data_packet(&key, &sealed.data_packet)?;
    let metadata: CalendarMetadataV1 = serde_json::from_slice(&json)
        .map_err(|_| CryptoError::InvalidInput("calendar metadata does not parse".into()))?;
    metadata.check()?;
    Ok((
        metadata,
        signed_by(&sealed.signature, &json, author_public_keys),
    ))
}

// ----- wire forms (the server's API and the browser) -----

/// One part on the wire: base64 data, armored signature.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventPartV1 {
    pub data: String,
    pub signature: String,
}

/// A sealed event on the wire (base64 packets).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedEventV1 {
    pub shared_key_packet: String,
    pub calendar_key_packet: String,
    pub shared_signed: EventPartV1,
    pub shared_encrypted: EventPartV1,
    pub calendar_signed: EventPartV1,
    pub calendar_encrypted: Option<EventPartV1>,
}

/// A calendar's sealed name and description on the wire.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedMetadataV1 {
    pub key_packet: String,
    pub data_packet: String,
    pub signature: String,
}

fn b64_decode(value: &str, what: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(value)
        .map_err(|_| CryptoError::InvalidInput(format!("{what} is not base64")))
}

impl EventPartV1 {
    fn of(part: &EventPart) -> Self {
        EventPartV1 {
            data: STANDARD.encode(&part.data),
            signature: part.signature.clone(),
        }
    }

    fn to_part(&self) -> Result<EventPart> {
        if self.signature.len() > 4096 {
            return Err(CryptoError::InvalidInput("signature is too large".into()));
        }
        Ok(EventPart {
            data: b64_decode(&self.data, "part")?,
            signature: self.signature.clone(),
        })
    }
}

impl SealedEventV1 {
    pub fn of(event: &SealedEvent) -> Self {
        SealedEventV1 {
            shared_key_packet: STANDARD.encode(&event.shared_key_packet),
            calendar_key_packet: STANDARD.encode(&event.calendar_key_packet),
            shared_signed: EventPartV1::of(&event.shared_signed),
            shared_encrypted: EventPartV1::of(&event.shared_encrypted),
            calendar_signed: EventPartV1::of(&event.calendar_signed),
            calendar_encrypted: event.calendar_encrypted.as_ref().map(EventPartV1::of),
        }
    }

    pub fn to_event(&self) -> Result<SealedEvent> {
        Ok(SealedEvent {
            shared_key_packet: b64_decode(&self.shared_key_packet, "key packet")?,
            calendar_key_packet: b64_decode(&self.calendar_key_packet, "key packet")?,
            shared_signed: self.shared_signed.to_part()?,
            shared_encrypted: self.shared_encrypted.to_part()?,
            calendar_signed: self.calendar_signed.to_part()?,
            calendar_encrypted: self
                .calendar_encrypted
                .as_ref()
                .map(EventPartV1::to_part)
                .transpose()?,
        })
    }
}

impl SealedMetadataV1 {
    pub fn of(sealed: &SealedMetadata) -> Self {
        SealedMetadataV1 {
            key_packet: STANDARD.encode(&sealed.key_packet),
            data_packet: STANDARD.encode(&sealed.data_packet),
            signature: sealed.signature.clone(),
        }
    }

    pub fn to_sealed(&self) -> Result<SealedMetadata> {
        Ok(SealedMetadata {
            key_packet: b64_decode(&self.key_packet, "key packet")?,
            data_packet: b64_decode(&self.data_packet, "data packet")?,
            signature: self.signature.clone(),
        })
    }
}

/// The packet builders, for this crate's tests and the server's live tests
/// that make malformed or misaddressed values (feature `test-vectors`, never
/// on for a client): a client seals only through [`UnlockedCalendarKey`] and
/// [`seal_passphrase`].
#[cfg(feature = "test-vectors")]
pub mod testing {
    use super::{Result, SessionKey};

    /// A key packet carrying `session_key` to `public_key`.
    pub fn key_packet_to(session_key: &SessionKey, public_key: &[u8]) -> Result<Vec<u8>> {
        super::key_packet_to(session_key, public_key)
    }

    /// A data packet of `plaintext` under `session_key`.
    pub fn encrypt_data_packet(session_key: &SessionKey, plaintext: &[u8]) -> Result<Vec<u8>> {
        super::encrypt_data_packet(session_key, plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mail_key::generate_address_key;

    #[test]
    fn a_calendar_key_locks_and_opens_its_packets() {
        let passphrase = Passphrase::generate();
        let key = generate_calendar_key(&passphrase, 1_760_000_000).unwrap();
        assert_eq!(
            inspect_calendar_public_key(&key.public_key).unwrap(),
            key.fingerprint
        );
        inspect_locked_calendar_key(&key.locked_secret_key, &key.public_key).unwrap();
        let other = generate_calendar_key(&passphrase, 1_760_000_000).unwrap();
        assert!(inspect_locked_calendar_key(&key.locked_secret_key, &other.public_key).is_err());
        let wrong = Passphrase::generate();
        assert!(matches!(
            unlock_calendar_key(&key.locked_secret_key, &wrong),
            Err(CryptoError::AuthFailed)
        ));
        let unlocked = unlock_calendar_key(&key.locked_secret_key, &passphrase).unwrap();
        assert_eq!(unlocked.public_key(), key.public_key.as_slice());
        let secret = unlocked.secret();

        let session_key = SessionKey::generate();
        let key_packet = key_packet_to(&session_key, &key.public_key).unwrap();
        assert_eq!(
            key_packet_key_id(&key_packet).unwrap(),
            encryption_key_id(&key.public_key).unwrap()
        );
        let opened = open_key_packet(&key_packet, secret).unwrap();
        assert_eq!(opened.as_bytes(), session_key.as_bytes());

        let data = encrypt_data_packet(&session_key, b"BEGIN:VCALENDAR").unwrap();
        assert_eq!(
            decrypt_data_packet(&opened, &data).unwrap().as_slice(),
            b"BEGIN:VCALENDAR"
        );
        assert!(matches!(
            decrypt_data_packet(&SessionKey::generate(), &data),
            Err(CryptoError::AuthFailed)
        ));
    }

    #[test]
    fn a_passphrase_opens_only_signed_by_the_owner() {
        let owner = generate_address_key("ada@example.org", 1_760_000_000).unwrap();
        let member = generate_address_key("bob@example.org", 1_760_000_000).unwrap();
        let stranger = generate_address_key("eve@example.org", 1_760_000_000).unwrap();
        let passphrase = Passphrase::generate();
        let sealed = seal_passphrase_to(
            &passphrase,
            &[&owner.public_key, &member.public_key],
            &owner.secret_key,
        )
        .unwrap();
        for (index, holder) in [&owner, &member].into_iter().enumerate() {
            let opened = open_passphrase(
                &sealed.key_packets[index],
                &sealed.data_packet,
                sealed.signature.as_bytes(),
                &holder.secret_key,
                &[&owner.public_key],
            )
            .unwrap();
            assert_eq!(opened.as_str(), passphrase.as_str());
        }
        // Signed by someone else: refused.
        assert!(matches!(
            open_passphrase(
                &sealed.key_packets[1],
                &sealed.data_packet,
                sealed.signature.as_bytes(),
                &member.secret_key,
                &[&stranger.public_key],
            ),
            Err(CryptoError::AuthFailed)
        ));
        // Someone else's key packet: refused.
        assert!(open_passphrase(
            &sealed.key_packets[0],
            &sealed.data_packet,
            sealed.signature.as_bytes(),
            &member.secret_key,
            &[&owner.public_key],
        )
        .is_err());
    }

    fn parts(uid: &str) -> EventParts {
        use crate::calendar_event::EventTime;
        let stamp = "2026-10-21T08:00:00Z".parse().unwrap();
        EventParts {
            shared_signed: SharedSigned {
                uid: uid.into(),
                dtstamp: stamp,
                dtstart: EventTime::Utc("2026-10-22T06:30:00Z".parse().unwrap()),
                dtend: Some(EventTime::Utc("2026-10-22T07:30:00Z".parse().unwrap())),
                recurrence_id: None,
                rrule: None,
                exdates: Vec::new(),
                organizer: None,
                sequence: 0,
            },
            shared_encrypted: SharedEncrypted {
                uid: uid.into(),
                dtstamp: Some(stamp),
                summary: Some("Planning".into()),
                ..Default::default()
            },
            calendar_signed: CalendarSigned {
                uid: uid.into(),
                dtstamp: stamp,
                exdates: Vec::new(),
                status: None,
                transp: None,
            },
            calendar_encrypted: None,
        }
    }

    #[test]
    fn an_event_seals_checks_and_opens() {
        let author = generate_address_key("ada@example.org", 1_760_000_000).unwrap();
        let other = generate_address_key("eve@example.org", 1_760_000_000).unwrap();
        let passphrase = Passphrase::generate();
        let calendar = generate_calendar_key(&passphrase, 1_760_000_000).unwrap();
        let unlocked = unlock_calendar_key(&calendar.locked_secret_key, &passphrase).unwrap();

        let sealed = unlocked
            .seal_event(&parts("u1@kutup"), &author.secret_key, None, None)
            .unwrap();
        // The server reads the times only from a part the author signed.
        let (shared, _) = check_signed_parts(&sealed, &[&author.public_key]).unwrap();
        assert_eq!(shared.uid, "u1@kutup");
        check_sealed_shape(&sealed, &calendar.public_key).unwrap();
        let elsewhere = generate_calendar_key(&passphrase, 1_760_000_000).unwrap();
        assert!(check_sealed_shape(&sealed, &elsewhere.public_key).is_err());
        assert!(matches!(
            check_signed_parts(&sealed, &[&other.public_key]),
            Err(CryptoError::AuthFailed)
        ));
        let mut moved = sealed.clone();
        moved.shared_signed.data = String::from_utf8(moved.shared_signed.data)
            .unwrap()
            .replace("20261022T063000Z", "20261023T063000Z")
            .into_bytes();
        assert!(check_signed_parts(&moved, &[&author.public_key]).is_err());

        let opened = unlocked.open_event(&sealed, &[&author.public_key]).unwrap();
        assert!(opened.verified);
        assert_eq!(
            opened.parts.shared_encrypted.summary.as_deref(),
            Some("Planning")
        );
        assert!(
            !unlocked
                .open_event(&sealed, &[&other.public_key])
                .unwrap()
                .verified
        );
        // Parts of two events: refused.
        assert!(unlocked
            .seal_event(
                &EventParts {
                    shared_encrypted: parts("u2@kutup").shared_encrypted,
                    ..parts("u1@kutup")
                },
                &author.secret_key,
                None,
                None,
            )
            .is_err());
    }

    /// A server that lists another key for a calendar can't make a client
    /// seal to it: the unlocked key seals to the key derived from its secret.
    #[test]
    fn a_substituted_public_key_is_never_sealed_to() {
        let author = generate_address_key("ada@example.org", 1_760_000_000).unwrap();
        let passphrase = Passphrase::generate();
        let calendar = generate_calendar_key(&passphrase, 1_760_000_000).unwrap();
        let servers = generate_calendar_key(&Passphrase::generate(), 1_760_000_000).unwrap();
        let unlocked = unlock_calendar_key(&calendar.locked_secret_key, &passphrase).unwrap();
        assert_ne!(unlocked.public_key(), servers.public_key.as_slice());
        let sealed = unlocked
            .seal_event(&parts("u1@kutup"), &author.secret_key, None, None)
            .unwrap();
        // The packets are to the calendar's own key, not the server's.
        check_sealed_shape(&sealed, &calendar.public_key).unwrap();
        assert!(check_sealed_shape(&sealed, &servers.public_key).is_err());
        let servers_unlocked = servers.unlocked;
        assert!(servers_unlocked
            .open_event(&sealed, &[&author.public_key])
            .is_err());
        let metadata = unlocked
            .seal_metadata("c1", "Work", "", &author.secret_key)
            .unwrap();
        assert!(servers_unlocked
            .open_metadata(&metadata, "c1", &[&author.public_key])
            .is_err());
    }

    /// A new calendar's passphrase is to the owner's own key, derived from
    /// the secret that signs it: there is no public key to substitute.
    #[test]
    fn the_passphrase_is_sealed_to_the_owners_own_key() {
        let owner = generate_address_key("ada@example.org", 1_760_000_000).unwrap();
        let servers = generate_address_key("eve@example.org", 1_760_000_000).unwrap();
        let passphrase = Passphrase::generate();
        let sealed = seal_passphrase(&passphrase, &owner.secret_key).unwrap();
        assert_eq!(sealed.key_packets.len(), 1);
        assert_eq!(
            key_packet_key_id(&sealed.key_packets[0]).unwrap(),
            encryption_key_id(&owner.public_key).unwrap()
        );
        let opened = open_passphrase(
            &sealed.key_packets[0],
            &sealed.data_packet,
            sealed.signature.as_bytes(),
            &owner.secret_key,
            &[&owner.public_key],
        )
        .unwrap();
        assert_eq!(opened.as_str(), passphrase.as_str());
        assert!(open_key_packet(&sealed.key_packets[0], &servers.secret_key).is_err());
    }

    /// Only a key locked as this crate locks one unlocks: no other S2K, so a
    /// server can't choose the work.
    #[test]
    fn a_key_locked_another_way_is_refused() {
        use pgp::types::{S2kParams, StringToKey};
        let passphrase = Passphrase::generate();
        let calendar = generate_calendar_key(&passphrase, 1_760_000_000).unwrap();
        let mut key = SignedSecretKey::from_bytes(calendar.unlocked.secret()).unwrap();
        let password = Password::from(passphrase.as_str());
        let costly = || S2kParams::Cfb {
            sym_alg: SymmetricKeyAlgorithm::AES256,
            s2k: StringToKey::IteratedAndSalted {
                hash_alg: pgp::crypto::hash::HashAlgorithm::Sha256,
                salt: [7; 8],
                count: 255,
            },
            iv: vec![0u8; 16].into(),
        };
        key.primary_key
            .set_password_with_s2k(&password, costly())
            .unwrap();
        for subkey in &mut key.secret_subkeys {
            subkey
                .key
                .set_password_with_s2k(&password, costly())
                .unwrap();
        }
        let locked = key.to_bytes().unwrap();
        assert!(unlock_calendar_key(&locked, &passphrase).is_err());
        assert!(inspect_locked_calendar_key(&locked, &calendar.public_key).is_err());
    }

    #[test]
    fn metadata_is_encrypted_to_the_calendar() {
        let author = generate_address_key("ada@example.org", 1_760_000_000).unwrap();
        let passphrase = Passphrase::generate();
        let calendar = generate_calendar_key(&passphrase, 1_760_000_000).unwrap();
        let unlocked = unlock_calendar_key(&calendar.locked_secret_key, &passphrase).unwrap();
        let sealed = unlocked
            .seal_metadata("c1", "Work", "Team, Q4", &author.secret_key)
            .unwrap();
        let (opened, verified) = unlocked
            .open_metadata(&sealed, "c1", &[&author.public_key])
            .unwrap();
        assert_eq!(
            (opened.name.as_str(), opened.description.as_str()),
            ("Work", "Team, Q4")
        );
        assert_eq!(opened.fingerprint, hex::encode(calendar.fingerprint));
        assert!(verified);
        // Served under another calendar's id: refused.
        assert!(unlocked
            .open_metadata(&sealed, "c2", &[&author.public_key])
            .is_err());
        assert!(unlocked
            .seal_metadata("c1", " ", "", &author.secret_key)
            .is_err());
    }
}
