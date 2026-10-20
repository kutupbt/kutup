//! Mail between the server's own users, as the apps send and read it: the
//! address's OpenPGP key made and published with its signed key list, a
//! message encrypted to both ends (`encrypt_split`), the inbox listed, and a
//! message downloaded and decrypted. Ported from the mail gate's helpers
//! (`crates/kutup-server/tests/mail_inbound_live.rs`).

use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::mail_key::{self, MailKeyEntryV1, MailKeyListV1, DEFAULT_FLAGS};
use reqwest::multipart::{Form, Part};
use serde_json::{json, Value};

use crate::account::User;
use crate::api::{self, Api};

pub struct Address {
    pub address: String,
    pub secret_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn hex32(value: String) -> Result<[u8; 32]> {
    let bytes = (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()?;
    bytes.try_into().map_err(|_| anyhow!("not 32 bytes"))
}

/// The user's address with a fresh key, published as the web does on first
/// opening Mail.
pub async fn set_up_address(api: &Api, user: &User) -> Result<Address> {
    let addresses = api::json(api.get("/mail/addresses", &user.token).send().await?).await?;
    let first = &addresses[0];
    let id = first["id"]
        .as_str()
        .ok_or_else(|| anyhow!("no address"))?
        .to_owned();
    let address = first["address"].as_str().unwrap_or_default().to_owned();
    let (master_key, binding, identity_incarnation, authority_key_id) = (
        user.master_key,
        user.binding.clone(),
        user.identity.incarnation_id(),
        user.identity.authority_key_id(),
    );
    let signing_key = user.identity.authority_signing_key().clone();
    let for_key = address.clone();
    let (key, envelope, list) = tokio::task::spawn_blocking(move || -> Result<_> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as u32;
        let key = mail_key::generate_address_key(&for_key, now)?;
        let envelope =
            mail_key::seal_address_key(&master_key, &binding, &for_key, &key.secret_key)?;
        let list = MailKeyListV1 {
            incarnation_id: hex32(identity_incarnation)?,
            authority_key_id: hex32(authority_key_id)?,
            address: for_key,
            sequence: 1,
            previous_hash: None,
            issued_at: time::OffsetDateTime::now_utc()
                .replace_nanosecond(0)?
                .format(&time::format_description::well_known::Rfc3339)?,
            keys: vec![MailKeyEntryV1 {
                fingerprint: key.fingerprint,
                sha256_fingerprint: key.sha256_fingerprint,
                primary: true,
                flags: DEFAULT_FLAGS,
            }],
        }
        .sign(&signing_key)?;
        Ok((key, envelope, list))
    })
    .await??;
    api::ok(
        api.post(&format!("/mail/addresses/{id}/keys"), &user.token)
            .json(&json!({
                "publicKey": b64(&key.public_key),
                "privateKeyEnvelope": b64(&envelope),
                "keyList": { "data": b64(&list.data), "signature": b64(&list.signature) },
            }))
            .send()
            .await?,
    )
    .await?;
    Ok(Address {
        address,
        secret_key: key.secret_key.to_vec(),
        public_key: key.public_key,
    })
}

fn form(parts: Vec<(&'static str, Vec<u8>)>) -> Form {
    parts.into_iter().fold(Form::new(), |form, (name, bytes)| {
        form.part(name, Part::bytes(bytes).file_name(name))
    })
}

/// A message from `from` to `to`, end-to-end encrypted.
pub async fn send(api: &Api, sender: &User, from: &Address, to: &Address) -> Result<()> {
    let domain = from
        .address
        .split_once('@')
        .map(|(_, d)| d)
        .unwrap_or_default();
    let message_id = format!("{}@{domain}", uuid::Uuid::new_v4().simple());
    let subject = "load test";
    let body = "x".repeat(2000);
    let mime = format!(
        "From: {}\r\nTo: {}\r\nSubject: {subject}\r\nMessage-ID: <{message_id}>\r\n\r\n{body}\r\n",
        from.address, to.address
    );
    let (from_public, to_public, secret) = (
        from.public_key.clone(),
        to.public_key.clone(),
        from.secret_key.clone(),
    );
    let split = tokio::task::spawn_blocking(move || {
        mail_key::encrypt_split(&[&from_public, &to_public], &secret, mime.as_bytes())
    })
    .await??;
    let meta = json!({
        "to": [{ "address": to.address }],
        "subject": subject,
        "messageId": message_id,
        "keyPackets": {
            "self": b64(&split.key_packets[0]),
            to.address.clone(): b64(&split.key_packets[1]),
        },
    });
    api::ok(
        api.post("/mail/send", &sender.token)
            .multipart(form(vec![
                ("meta", serde_json::to_vec(&meta)?),
                ("data", split.data_packet),
            ]))
            .send()
            .await?,
    )
    .await?;
    Ok(())
}

/// The inbox's first page.
pub async fn list(api: &Api, user: &User) -> Result<Vec<Value>> {
    let page = api::json(
        api.get("/mail/messages?folder=inbox", &user.token)
            .send()
            .await?,
    )
    .await?;
    Ok(page["messages"].as_array().cloned().unwrap_or_default())
}

/// Downloads a message and decrypts it.
pub async fn open(api: &Api, user: &User, address: &Address, id: &str) -> Result<()> {
    let stored = api::ok(
        api.get(&format!("/mail/messages/{id}/content"), &user.token)
            .send()
            .await?,
    )
    .await?
    .bytes()
    .await?;
    let secret = address.secret_key.clone();
    tokio::task::spawn_blocking(move || mail_key::decrypt(&secret, &stored, None).map(drop))
        .await??;
    Ok(())
}
