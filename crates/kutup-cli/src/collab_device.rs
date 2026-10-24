//! The CLI's collaboration device (docs/plans/device-registration.md): the
//! Ed25519 key its edits to notes, code files and place lists are signed
//! with, registered under the account authority's statement, as a browser
//! tab's is.

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::device_registration::{self, DeviceStatement, PURPOSE_COLLAB_FRAMES};
use kutup_crypto::identity::AccountIdentityKeysV1;
use zeroize::Zeroizing;

use crate::api::collab;
use crate::api::{ApiError, Client};
use crate::session::{CollabDevice, Session, Store};

/// After this long the CLI renews its statement: other servers trust one 30
/// days, so a device in use never lapses.
const RENEW_AFTER_MS: i64 = 15 * 24 * 3600 * 1000;

/// A registered device, ready to sign frames.
pub struct Device {
    pub id: i64,
    seed: Zeroizing<[u8; 32]>,
}

impl Device {
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }
}

pub fn now_ms() -> i64 {
    (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64
}

/// Whether `error` is the server saying this device is not (or no longer)
/// the account's: register again.
pub fn not_authorized(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|e| e.downcast_ref::<ApiError>())
        .any(|e| e.status == 403 && e.code.as_deref() == Some("deviceNotAuthorized"))
}

/// What signs device statements: the account and this server's name.
pub struct Signer<'a> {
    client: &'a Client,
    store: &'a Store,
    sess: &'a Session,
    server: String,
    identity: AccountIdentityKeysV1,
}

impl<'a> Signer<'a> {
    pub fn new(client: &'a Client, store: &'a Store, sess: &'a Session) -> Result<Self> {
        if sess.master_key.is_empty() {
            return Err(anyhow!(
                "this session holds no account keys; sign in again to edit notes and lists"
            ));
        }
        let master_key: [u8; 32] = sess
            .master_key_bytes()?
            .as_slice()
            .try_into()
            .context("master key must be 32 bytes")?;
        Ok(Signer {
            client,
            store,
            sess,
            server: client.settings()?.chat.server_name,
            identity: AccountIdentityKeysV1::derive(&master_key)?,
        })
    }

    fn statement(&self, public: &[u8; 32], issued_at_ms: i64) -> Result<(String, String)> {
        let challenge_b64 = self.client.device_challenge()?;
        let challenge: [u8; 32] = STANDARD
            .decode(&challenge_b64)?
            .try_into()
            .map_err(|_| anyhow!("the server sent a malformed challenge"))?;
        let signature = device_registration::sign(
            &self.identity,
            &DeviceStatement {
                server: &self.server,
                user_id: &self.sess.user_id,
                device_public: public,
                purpose: PURPOSE_COLLAB_FRAMES,
                challenge: &challenge,
                issued_at_ms,
            },
        )?;
        Ok((challenge_b64, signature))
    }

    /// This profile's device: the one kept (renewed when due), or a new one
    /// registered now.
    pub fn device(&self) -> Result<Device> {
        if let Some(kept) = self.store.collab_device()? {
            if kept.server == self.server && kept.user_id == self.sess.user_id {
                match self.renewed(kept) {
                    Ok(device) => return Ok(device),
                    // Revoked, or of an earlier identity: a new one.
                    Err(e) if not_authorized(&e) => {}
                    Err(e) => return Err(e),
                }
            }
        }
        self.register()
    }

    /// The server no longer takes this profile's device: renewed under this
    /// sign-in if it is only its old sign-in that ended (the same key, no new
    /// slot under the cap), else a new one.
    pub fn recover(&self) -> Result<Device> {
        if let Some(mut kept) = self.store.collab_device()? {
            if kept.server == self.server && kept.user_id == self.sess.user_id {
                kept.issued_at_ms = 0; // due now
                match self.renewed(kept) {
                    Ok(device) => return Ok(device),
                    Err(e) if not_authorized(&e) => {}
                    Err(e) => return Err(e),
                }
            }
        }
        self.register()
    }

    fn renewed(&self, mut kept: CollabDevice) -> Result<Device> {
        let seed: [u8; 32] = STANDARD
            .decode(&kept.seed)?
            .try_into()
            .map_err(|_| anyhow!("stored device key has the wrong length"))?;
        let seed = Zeroizing::new(seed);
        let now = now_ms();
        if now - kept.issued_at_ms > RENEW_AFTER_MS {
            let public = kutup_crypto::primitives::SigningKey::from_seed(
                kutup_crypto::primitives::Suite::V1,
                &seed,
            )
            .verifying_key()
            .to_array::<32>();
            let (challenge, signature) = self.statement(&public, now)?;
            self.client.renew_device(
                kept.device_id,
                &collab::DeviceStatement {
                    challenge: &challenge,
                    issued_at_ms: now,
                    signature: &signature,
                },
            )?;
            kept.issued_at_ms = now;
            self.store.put_collab_device(Some(&kept))?;
        }
        Ok(Device {
            id: kept.device_id,
            seed,
        })
    }

    /// Registers a new device and keeps it.
    pub fn register(&self) -> Result<Device> {
        let mut seed = Zeroizing::new([0u8; 32]);
        kutup_crypto::primitives::random(seed.as_mut());
        let public = kutup_crypto::primitives::SigningKey::from_seed(
            kutup_crypto::primitives::Suite::V1,
            &seed,
        )
        .verifying_key()
        .to_array::<32>();
        let now = now_ms();
        let (challenge, signature) = self.statement(&public, now)?;
        let id = self
            .client
            .register_device(
                &STANDARD.encode(public),
                "Kutup CLI",
                &collab::DeviceStatement {
                    challenge: &challenge,
                    issued_at_ms: now,
                    signature: &signature,
                },
            )
            .context("register this CLI's collaboration device")?;
        self.store.put_collab_device(Some(&CollabDevice {
            server: self.server.clone(),
            user_id: self.sess.user_id.clone(),
            device_id: id,
            seed: STANDARD.encode(seed.as_ref()),
            issued_at_ms: now,
        }))?;
        Ok(Device { id, seed })
    }
}
