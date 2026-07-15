//! Conversion between the `kutup-chat-proto` wire types and libsignal. All
//! base64 decoding and libsignal (de)serialization lives here so the rest of
//! the engine works in kutup/libsignal native types, never raw bytes.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use libsignal_protocol::*;

use crate::address::device_id_u8;
use crate::error::{crypto, ChatError, Result};
use kutup_chat_proto::{DevicePreKeyBundle, EnvelopeType};

fn dec(field: &str, b64: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(b64)
        .map_err(|e| ChatError::Wire(format!("{field}: {e}")))
}

/// Converts a served bundle into the libsignal `PreKeyBundle` the sender feeds
/// to `process_prekey_bundle`. Signatures are carried through verbatim for
/// libsignal to verify against the identity key.
pub(crate) fn to_prekey_bundle(b: &DevicePreKeyBundle) -> Result<PreKeyBundle> {
    let identity = crypto(IdentityKey::decode(&dec("identityKey", &b.identity_key)?))?;

    let signed_pub = crypto(PublicKey::deserialize(&dec(
        "signedPreKey.publicKey",
        &b.signed_pre_key.public_key,
    )?))?;
    let signed_sig = dec(
        "signedPreKey.signature",
        b.signed_pre_key
            .signature
            .as_deref()
            .ok_or_else(|| ChatError::Wire("signedPreKey missing signature".into()))?,
    )?;

    let kyber_pub = crypto(kem::PublicKey::deserialize(&dec(
        "kyberPreKey.publicKey",
        &b.kyber_pre_key.public_key,
    )?))?;
    let kyber_sig = dec("kyberPreKey.signature", &b.kyber_pre_key.signature)?;

    let one_time = match &b.one_time_pre_key {
        Some(k) => {
            let pk = crypto(PublicKey::deserialize(&dec(
                "oneTimePreKey.publicKey",
                &k.public_key,
            )?))?;
            Some((k.key_id.into(), pk))
        }
        None => None,
    };

    let device_id = device_id_u8(b.device_id)?;

    crypto(PreKeyBundle::new(
        b.registration_id,
        device_id,
        one_time,
        b.signed_pre_key.key_id.into(),
        signed_pub,
        signed_sig,
        b.kyber_pre_key.key_id.into(),
        kyber_pub,
        kyber_sig,
        identity,
    ))
}

/// Decodes a bundle's base64 `identityKey` into a libsignal `IdentityKey` — used
/// when accepting a reinstalled peer's changed identity (safety-number change).
pub(crate) fn decode_identity_key(b64: &str) -> Result<IdentityKey> {
    crypto(IdentityKey::decode(&dec("identityKey", b64)?))
}

/// Serializes a libsignal ciphertext into the envelope's `(type, content)`.
pub(crate) fn encode_ciphertext(msg: &CiphertextMessage) -> Result<(EnvelopeType, String)> {
    let ty = match msg.message_type() {
        CiphertextMessageType::PreKey => EnvelopeType::PreKey,
        CiphertextMessageType::Whisper => EnvelopeType::Message,
        other => {
            return Err(ChatError::Invalid(format!(
                "unsupported message type {other:?}"
            )))
        }
    };
    Ok((ty, STANDARD.encode(msg.serialize())))
}

/// Reparses an envelope's `(type, content)` back into a libsignal ciphertext.
pub(crate) fn decode_ciphertext(ty: EnvelopeType, content: &str) -> Result<CiphertextMessage> {
    let bytes = dec("content", content)?;
    Ok(match ty {
        EnvelopeType::PreKey => CiphertextMessage::PreKeySignalMessage(crypto(
            PreKeySignalMessage::try_from(bytes.as_slice()),
        )?),
        EnvelopeType::Message => {
            CiphertextMessage::SignalMessage(crypto(SignalMessage::try_from(bytes.as_slice()))?)
        }
    })
}
