//! Calendars (docs/plans/calendar.md, E1): Proton Calendar's keys and
//! packets, through rPGP as Mail's address keys, with the passphrase on the
//! account's keys (docs/plans/wipe-unification.md, W4).
//!
//! - Each calendar has its own OpenPGP key, in the address keys' shape, its
//!   secret locked with a passphrase (`generateCalendarKey`; user ID
//!   "Calendar key", so an exported key confuses no one).
//! - The passphrase is the base64 text of 32 random bytes. Each member holds
//!   it as a [`CalendarShareEnvelopeV1`]: the 32 bytes sealed with X-Wing
//!   HPKE to the member's account key (the Drive HPKE key their identity
//!   root derives) and signed by the owner's account signing key, bound to
//!   the calendar, its key generation and both accounts by id and
//!   incarnation, never by an address. The owner's own copy is a share to
//!   itself. A rename or a removed address changes none of it, and the wrap
//!   is post-quantum. (Proton wraps it to address keys, the only account key
//!   its peers see; Kutup's peers verify the account key.)
//! - Events and the calendar's encrypted metadata are data packets under
//!   session keys wrapped to the calendar key, each part signed (detached)
//!   by its author's address key ([`crate::calendar_event`]), as Proton's.
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
use zeroize::Zeroizing;

use crate::account_ref::AccountRef;
use crate::calendar_event::{CalendarEncrypted, CalendarSigned, SharedEncrypted, SharedSigned};
use crate::error::{CryptoError, Result};
use crate::format::Extra;
use crate::identity::AccountIdentityKeysV1;
use crate::mail_key::{
    backend, encryption_subkey, fingerprint_of, generate_key, packet_extent, parse_recipient,
    sign_detached, verify_detached, FINGERPRINT_LEN,
};
pub use crate::named_share::CalendarShareEnvelopeV1;

/// The calendar key's user ID, as Proton's.
pub const CALENDAR_KEY_USER_ID: &str = "Calendar key";
/// Random bytes in a calendar's passphrase (its text is their base64).
pub const PASSPHRASE_BYTES: usize = 32;
/// A calendar's first key generation; a new key (E3, when a member is
/// removed) takes the next, and every share names the one it unlocks.
pub const FIRST_KEY_GENERATION: u32 = 1;
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
        crate::primitives::random(key.as_mut());
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
        crate::primitives::random(bytes.as_mut());
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

    /// The passphrase whose bytes a share carries.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PASSPHRASE_BYTES {
            return Err(CryptoError::InvalidInput(
                "a passphrase is 32 random bytes".into(),
            ));
        }
        Ok(Passphrase(Zeroizing::new(STANDARD.encode(bytes))))
    }

    /// The 32 bytes a share carries.
    pub(crate) fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(
            STANDARD
                .decode(self.0.as_bytes())
                .expect("a passphrase's text is base64"),
        )
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
    /// The key ID of the encryption subkey, as key packets to this key name
    /// it: a client holding several key generations opens an event with the
    /// one its key packets name ([`event_key_id`]).
    pub fn key_id(&self) -> Result<[u8; 8]> {
        encryption_key_id(&self.public)
    }

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
        self.seal_metadata_keeping(
            calendar_id,
            name,
            description,
            &CalendarMetadataRest::default(),
            author_secret_key,
        )
    }

    /// [`Self::seal_metadata`] for a rename: the version and the fields a
    /// newer client wrote (`rest`, from the opened metadata) are sealed again
    /// unchanged (docs/plans/format-evolution.md, rule 3).
    pub fn seal_metadata_keeping(
        &self,
        calendar_id: &str,
        name: &str,
        description: &str,
        rest: &CalendarMetadataRest,
        author_secret_key: &[u8],
    ) -> Result<SealedMetadata> {
        let metadata = CalendarMetadataV1 {
            version: rest.v,
            min: rest.min,
            calendar_id: calendar_id.to_owned(),
            fingerprint: hex::encode(self.fingerprint),
            name: name.to_owned(),
            description: description.to_owned(),
            extra: rest.extra.clone(),
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

    /// A link's optional purpose (docs/plans/calendar-e3.md §3, Proton's
    /// link label), sealed to this calendar's key and bound to the calendar
    /// and the link, signed by the owner's address key: the server holds the
    /// calendar's public key, so without the signature it could write one.
    pub fn seal_link_purpose(
        &self,
        calendar_id: &str,
        link_id: &str,
        purpose: &str,
        author_secret_key: &[u8],
    ) -> Result<SealedMetadata> {
        let sealed = LinkPurposeV1 {
            version: LINK_PURPOSE_VERSION,
            calendar_id: calendar_id.to_owned(),
            link_id: link_id.to_owned(),
            purpose: purpose.to_owned(),
        };
        sealed.check()?;
        let json = serde_json::to_vec(&sealed).map_err(backend)?;
        let key = SessionKey::generate();
        Ok(SealedMetadata {
            key_packet: key_packet_to(&key, &self.public)?,
            data_packet: encrypt_data_packet(&key, &json)?,
            signature: sign_detached(author_secret_key, &json)?,
        })
    }

    /// Opens a link's purpose: refused unless it names `calendar_id` and
    /// `link_id`; `verified` says whether one of the given address keys (the
    /// owner's) signed it. A purpose sealed under an older key generation
    /// opens with that generation's key.
    pub fn open_link_purpose(
        &self,
        sealed: &SealedMetadata,
        calendar_id: &str,
        link_id: &str,
        author_public_keys: &[&[u8]],
    ) -> Result<(String, bool)> {
        let key = open_key_packet(&sealed.key_packet, &self.secret)?;
        let json = decrypt_data_packet(&key, &sealed.data_packet)?;
        crate::format::check_json_version("calendar link purpose", &json, LINK_PURPOSE_VERSION)?;
        let opened: LinkPurposeV1 = serde_json::from_slice(&json)
            .map_err(|_| CryptoError::InvalidInput("a link purpose does not parse".into()))?;
        opened.check()?;
        if opened.calendar_id != calendar_id || opened.link_id != link_id {
            return Err(CryptoError::InvalidInput(
                "the purpose is another link's".into(),
            ));
        }
        Ok((
            opened.purpose,
            signed_by(&sealed.signature, &json, author_public_keys),
        ))
    }

    /// Opens a key packet to this calendar's key.
    pub fn open_key_packet(&self, key_packet: &[u8]) -> Result<SessionKey> {
        open_key_packet(key_packet, &self.secret)
    }

    /// A key packet `older` (an older generation of this calendar) opens,
    /// sealed again to this key: the same session key, so the parts it
    /// opens (and their signatures) stay as they are. How a calendar's
    /// events move to its newest generation before older ones are pruned
    /// (docs/plans/calendar-e3.md, "Compaction").
    pub fn rewrap_key_packet(
        &self,
        older: &UnlockedCalendarKey,
        key_packet: &[u8],
    ) -> Result<Vec<u8>> {
        let session_key = older.open_key_packet(key_packet)?;
        key_packet_to(&session_key, &self.public)
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
        .set_password(crate::primitives::Rng, &password)
        .map_err(backend)?;
    for subkey in &mut key.secret_subkeys {
        subkey
            .key
            .set_password(crate::primitives::Rng, &password)
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
/// (version 3, as the address keys use): an event's or the metadata's key
/// packet to its calendar.
pub(crate) fn key_packet_to(session_key: &SessionKey, public_key: &[u8]) -> Result<Vec<u8>> {
    let recipient = parse_recipient(public_key)?;
    let subkey = encryption_subkey(&recipient)?;
    let raw = session_key.0.to_vec().into();
    let pkesk = PublicKeyEncryptedSessionKey::from_session_key_v3(
        crate::primitives::Rng,
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
        .seipd_v1(crate::primitives::Rng, SymmetricKeyAlgorithm::AES256);
    builder
        .set_session_key(session_key.0.to_vec().into())
        .map_err(backend)?;
    let packet = builder.to_vec(crate::primitives::Rng).map_err(backend)?;
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

/// A member a calendar's passphrase is shared with: their account, its
/// incarnation (lowercase hex) and its account HPKE key, as their verified
/// key binding names them.
pub struct CalendarMember<'a> {
    pub account: &'a AccountRef,
    pub incarnation_id: &'a str,
    pub xwing_public_key: &'a [u8],
}

/// A calendar's owner as a member checks their share: their account, its
/// incarnation (lowercase hex) and its account signing key, verified.
pub struct CalendarOwner<'a> {
    pub account: &'a AccountRef,
    pub incarnation_id: &'a str,
    pub signing_public_key: &'a [u8],
}

/// Shares `passphrase` (the calendar `calendar_id`'s, at `key_generation`)
/// with `member`, signed by the owner `owner` with its identity's account
/// signing key. Sharing (E3) adds members through it; the owner's own copy
/// is [`seal_own_passphrase`].
pub fn seal_passphrase(
    passphrase: &Passphrase,
    calendar_id: &str,
    key_generation: u32,
    owner: &AccountRef,
    owner_identity: &AccountIdentityKeysV1,
    member: &CalendarMember<'_>,
) -> Result<CalendarShareEnvelopeV1> {
    CalendarShareEnvelopeV1::seal(
        &passphrase.to_bytes(),
        calendar_id,
        key_generation,
        owner,
        &owner_identity.incarnation_id(),
        owner_identity.drive_signing_key(),
        member.account,
        member.incarnation_id,
        member.xwing_public_key,
    )
}

/// The owner's own copy of a new calendar's passphrase: a share to itself,
/// to the account key its identity derives, never to one a server hands over
/// (#307 review N1).
pub fn seal_own_passphrase(
    passphrase: &Passphrase,
    calendar_id: &str,
    key_generation: u32,
    owner: &AccountRef,
    owner_identity: &AccountIdentityKeysV1,
) -> Result<CalendarShareEnvelopeV1> {
    let incarnation_id = owner_identity.incarnation_id();
    seal_passphrase(
        passphrase,
        calendar_id,
        key_generation,
        owner,
        owner_identity,
        &CalendarMember {
            account: owner,
            incarnation_id: &incarnation_id,
            xwing_public_key: &owner_identity.drive_xwing_public_key(),
        },
    )
}

/// Opens a member's share of a calendar's passphrase with the member's
/// identity: refused unless it names this calendar, key generation, owner
/// and member, and the owner's account signing key signed it. A server can't
/// hand a member a passphrase of its own.
pub fn open_passphrase(
    share: &CalendarShareEnvelopeV1,
    calendar_id: &str,
    key_generation: u32,
    owner: &CalendarOwner<'_>,
    member: &AccountRef,
    member_identity: &AccountIdentityKeysV1,
) -> Result<Passphrase> {
    let bytes = Zeroizing::new(share.open(
        calendar_id,
        key_generation,
        owner.account,
        owner.incarnation_id,
        owner.signing_public_key,
        member,
        &member_identity.incarnation_id(),
        member_identity.drive_xwing_private_key(),
    )?);
    Passphrase::from_bytes(&bytes)
}

/// Opens the owner's own copy: the share from `account` to itself, checked
/// against the keys its identity derives.
pub fn open_own_passphrase(
    share: &CalendarShareEnvelopeV1,
    calendar_id: &str,
    key_generation: u32,
    account: &AccountRef,
    identity: &AccountIdentityKeysV1,
) -> Result<Passphrase> {
    let incarnation_id = identity.incarnation_id();
    open_passphrase(
        share,
        calendar_id,
        key_generation,
        &CalendarOwner {
            account,
            incarnation_id: &incarnation_id,
            signing_public_key: &identity.drive_signing_public_key(),
        },
        account,
        identity,
    )
}

/// The key ID a key packet is encrypted to (a server checks that an event's
/// and the metadata's key packets name the calendar key).
pub fn key_packet_key_id(key_packet: &[u8]) -> Result<[u8; 8]> {
    let (tag, _, length) = packet_extent(key_packet)?;
    if tag != TAG_PKESK || length != key_packet.len() {
        return Err(CryptoError::InvalidInput("not a single key packet".into()));
    }
    crate::mail_key::key_packet_key_id(key_packet)
}

/// The key ID an event's key packets are to (both name the same key, as
/// [`check_sealed_shape`] checks): which key generation opens it.
pub fn event_key_id(event: &SealedEvent) -> Result<[u8; 8]> {
    let shared = key_packet_key_id(&event.shared_key_packet)?;
    if key_packet_key_id(&event.calendar_key_packet)? != shared {
        return Err(CryptoError::InvalidInput(
            "an event's key packets name two keys".into(),
        ));
    }
    Ok(shared)
}

/// The key generation after `generation` (docs/plans/calendar-e3.md §2):
/// a removed member's rotation makes it.
pub fn next_key_generation(generation: u32) -> Result<u32> {
    generation
        .checked_add(1)
        .filter(|g| *g > FIRST_KEY_GENERATION)
        .ok_or_else(|| CryptoError::InvalidInput("no key generation after this one".into()))
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

/// The newest calendar metadata version this reader knows.
pub const CALENDAR_METADATA_VERSION: u16 = 1;

/// A calendar's name and description: `v` first, `min` when below it, and
/// the fields a newer client added, kept (docs/plans/format-evolution.md).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CalendarMetadataV1 {
    #[serde(rename = "v")]
    pub version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<u16>,
    /// The calendar it names, and the fingerprint (hex) of its key: signed
    /// with the name, so a server can't serve it under another calendar.
    pub calendar_id: String,
    pub fingerprint: String,
    pub name: String,
    pub description: String,
    #[serde(flatten, default, skip_serializing_if = "Extra::is_empty")]
    pub extra: Extra,
}

/// What a rename seals again besides the name and description: the
/// metadata's version and the fields a newer client added.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CalendarMetadataRest {
    pub v: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<u16>,
    #[serde(flatten, default)]
    pub extra: Extra,
}

impl Default for CalendarMetadataRest {
    fn default() -> Self {
        Self {
            v: CALENDAR_METADATA_VERSION,
            min: None,
            extra: Extra::new(),
        }
    }
}

impl CalendarMetadataV1 {
    /// Its version and unknown fields, for [`UnlockedCalendarKey::seal_metadata_keeping`].
    pub fn rest(&self) -> CalendarMetadataRest {
        CalendarMetadataRest {
            v: self.version,
            min: self.min,
            extra: self.extra.clone(),
        }
    }
}

/// A link purpose's format version.
const LINK_PURPOSE_VERSION: u16 = 1;
/// The longest link purpose, in characters (Proton's label limit).
pub const MAX_LINK_PURPOSE_CHARS: usize = 100;

/// A link's purpose as sealed.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LinkPurposeV1 {
    #[serde(rename = "v")]
    version: u16,
    calendar_id: String,
    link_id: String,
    purpose: String,
}

impl LinkPurposeV1 {
    fn check(&self) -> Result<()> {
        if self.calendar_id.is_empty()
            || self.calendar_id.len() > 64
            || self.link_id.is_empty()
            || self.link_id.len() > 64
            || self.purpose.trim().is_empty()
            || self.purpose.chars().count() > MAX_LINK_PURPOSE_CHARS
            || self.purpose.chars().any(char::is_control)
        {
            return Err(CryptoError::InvalidInput(
                "a link purpose is invalid".into(),
            ));
        }
        Ok(())
    }
}

/// The longest name and description, in characters (Proton's).
pub const MAX_CALENDAR_NAME_CHARS: usize = 100;
pub const MAX_CALENDAR_DESCRIPTION_CHARS: usize = 255;

impl CalendarMetadataV1 {
    fn check(&self) -> Result<()> {
        crate::format::check_version(
            "calendar metadata",
            self.version,
            self.min,
            CALENDAR_METADATA_VERSION,
        )?;
        crate::format::check_extra("calendar metadata", &self.extra)?;
        if self.calendar_id.is_empty()
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
    crate::format::check_json_version("calendar metadata", &json, CALENDAR_METADATA_VERSION)?;
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
/// [`seal_own_passphrase`] or [`seal_passphrase`].
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
    #[test]
    fn a_rewrapped_key_packet_opens_with_the_newer_key_only() {
        let (old_pass, new_pass) = (Passphrase::generate(), Passphrase::generate());
        let old = generate_calendar_key(&old_pass, 1_790_000_000)
            .unwrap()
            .unlocked;
        let new = generate_calendar_key(&new_pass, 1_790_000_100)
            .unwrap()
            .unlocked;
        let session = SessionKey::generate();
        let packet = key_packet_to(&session, old.public_key()).unwrap();
        let moved = new.rewrap_key_packet(&old, &packet).unwrap();
        assert_eq!(key_packet_key_id(&moved).unwrap(), new.key_id().unwrap());
        assert_eq!(
            new.open_key_packet(&moved).unwrap().as_bytes(),
            session.as_bytes()
        );
        assert!(old.open_key_packet(&moved).is_err());
        // A packet the older key can't open is refused.
        assert!(old.rewrap_key_packet(&new, &packet).is_err());
    }

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

    fn identity(seed: u8) -> AccountIdentityKeysV1 {
        AccountIdentityKeysV1::derive(&crate::account_roots::IdentityRoot::from_bytes([seed; 32]))
            .unwrap()
    }

    fn account(id: &str) -> AccountRef {
        AccountRef::new("kutup.test", id).unwrap()
    }

    const CALENDAR: &str = "6f1d3c2a-8b4e-4f7a-9c1d-2e3f4a5b6c7d";

    #[test]
    fn the_owner_holds_the_passphrase_on_its_account_key() {
        let ada = account("00000000-0000-4000-8000-0000000000a1");
        let ada_keys = identity(1);
        let passphrase = Passphrase::generate();
        let share =
            seal_own_passphrase(&passphrase, CALENDAR, FIRST_KEY_GENERATION, &ada, &ada_keys)
                .unwrap();
        let share = CalendarShareEnvelopeV1::decode_b64(&share.encode_b64().unwrap()).unwrap();
        let opened =
            open_own_passphrase(&share, CALENDAR, FIRST_KEY_GENERATION, &ada, &ada_keys).unwrap();
        assert_eq!(opened.as_str(), passphrase.as_str());
        // Another calendar, another key generation, another account or a
        // later incarnation of the same one: refused.
        let other = "7f1d3c2a-8b4e-4f7a-9c1d-2e3f4a5b6c7d";
        assert!(open_own_passphrase(&share, other, 1, &ada, &ada_keys).is_err());
        assert!(open_own_passphrase(&share, CALENDAR, 2, &ada, &ada_keys).is_err());
        let eve = account("00000000-0000-4000-8000-0000000000e1");
        assert!(open_own_passphrase(&share, CALENDAR, 1, &eve, &ada_keys).is_err());
        assert!(open_own_passphrase(&share, CALENDAR, 1, &ada, &identity(3)).is_err());
        // Never a Drive share: its own magic and HPKE info.
        let bytes = share.encode().unwrap();
        assert!(crate::named_share::NamedShareEnvelopeV1::decode(&bytes).is_err());
    }

    #[test]
    fn a_member_opens_only_what_the_owner_signed() {
        let ada = account("00000000-0000-4000-8000-0000000000a1");
        let bob = account("00000000-0000-4000-8000-0000000000b1");
        let (ada_keys, bob_keys, eve_keys) = (identity(1), identity(2), identity(3));
        let passphrase = Passphrase::generate();
        let bob_incarnation = bob_keys.incarnation_id();
        let share = seal_passphrase(
            &passphrase,
            CALENDAR,
            FIRST_KEY_GENERATION,
            &ada,
            &ada_keys,
            &CalendarMember {
                account: &bob,
                incarnation_id: &bob_incarnation,
                xwing_public_key: &bob_keys.drive_xwing_public_key(),
            },
        )
        .unwrap();
        let ada_incarnation = ada_keys.incarnation_id();
        let owner = |signing: &[u8; 32]| -> Result<Passphrase> {
            open_passphrase(
                &share,
                CALENDAR,
                FIRST_KEY_GENERATION,
                &CalendarOwner {
                    account: &ada,
                    incarnation_id: &ada_incarnation,
                    signing_public_key: signing,
                },
                &bob,
                &bob_keys,
            )
        };
        assert_eq!(
            owner(&ada_keys.drive_signing_public_key())
                .unwrap()
                .as_str(),
            passphrase.as_str()
        );
        // Signed by someone else: refused.
        assert!(matches!(
            owner(&eve_keys.drive_signing_public_key()),
            Err(CryptoError::AuthFailed)
        ));
        // Someone else's share: Ada's own copy doesn't open for Bob.
        let own = seal_own_passphrase(&passphrase, CALENDAR, FIRST_KEY_GENERATION, &ada, &ada_keys)
            .unwrap();
        assert!(open_passphrase(
            &own,
            CALENDAR,
            FIRST_KEY_GENERATION,
            &CalendarOwner {
                account: &ada,
                incarnation_id: &ada_incarnation,
                signing_public_key: &ada_keys.drive_signing_public_key(),
            },
            &bob,
            &bob_keys,
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
                other: Vec::new(),
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
                other: Vec::new(),
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
