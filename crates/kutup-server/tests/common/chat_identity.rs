//! Chat devices under one account identity (docs/plans/account-identity-key.md),
//! as the clients make them: a libsignal identity for the account, each
//! device's registration id and prekeys signed by it, its credential, and the
//! account's V2 manifests signed by its authority. The request bodies are the
//! kutup-chat-proto types, so they are what chat-core sends.
//!
//! - [`ChatAccount::reregister`]: the account's first device (or a new
//!   identity): device 1, under a manifest listing it alone.
//! - [`ChatAccount::link`]: a further device, with a link token one of the
//!   account's devices asked for, then the manifest listing every device.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signer as _, SigningKey};
use kutup_chat_proto::{
    AccountIdentitySuiteId, AccountManifestDeviceV2, AccountManifestDriveKeysV1, AccountManifestV2,
    AccountRef, DeviceRegistrationV1, DirectChatSuiteId, EcPreKey, KemPreKey,
    RegisterChatDeviceRequestV2, CHAT_DEVICE_HEADER,
};
use kutup_crypto::identity::AccountIdentityKeysV1;
use libsignal_protocol::{kem, IdentityKeyPair, KeyPair};
use rand::RngCore;
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::StatusCode;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::User;

/// One of an account's Chat devices.
#[derive(Clone)]
pub struct ChatDevice {
    pub id: u32,
    pub registration_id: u32,
    pub credential: [u8; 32],
}

impl ChatDevice {
    /// The `X-Kutup-Chat-Device` value.
    pub fn header(&self) -> String {
        format!("{}.{}", self.id, URL_SAFE_NO_PAD.encode(self.credential))
    }

    /// `request` made as this device (its credential beside the JWT).
    pub fn auth(&self, request: RequestBuilder) -> RequestBuilder {
        request.header(CHAT_DEVICE_HEADER, self.header())
    }
}

/// An account's Chat identity, its authority and its devices.
pub struct ChatAccount {
    pub account: AccountRef,
    pub token: String,
    pub authority: SigningKey,
    pub drive: AccountManifestDriveKeysV1,
    pub identity: IdentityKeyPair,
    pub devices: Vec<ChatDevice>,
    /// The account's current V2 manifest (none before its first device).
    pub head: Option<AccountManifestV2>,
}

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// A device's keys under `identity`: a signed EC prekey, a last-resort
/// Kyber1024 key, and one one-time key of each kind (the Kyber one signed).
pub fn device_keys(
    identity: &IdentityKeyPair,
) -> (EcPreKey, KemPreKey, Vec<EcPreKey>, Vec<KemPreKey>) {
    let mut rng = rand09::rng();
    let sign = |message: &[u8]| {
        b64(&identity
            .private_key()
            .calculate_signature(message, &mut rand09::rng())
            .unwrap())
    };
    let signed = KeyPair::generate(&mut rng).public_key.serialize();
    let last_resort = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng)
        .public_key
        .serialize();
    let one_time_kyber = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng)
        .public_key
        .serialize();
    let one_time = KeyPair::generate(&mut rng).public_key.serialize();
    (
        EcPreKey {
            key_id: 1,
            public_key: b64(&signed),
            signature: Some(sign(&signed)),
        },
        KemPreKey {
            key_id: 1,
            public_key: b64(&last_resort),
            signature: sign(&last_resort),
        },
        vec![EcPreKey {
            key_id: 10,
            public_key: b64(&one_time),
            signature: None,
        }],
        vec![KemPreKey {
            key_id: 20,
            public_key: b64(&one_time_kyber),
            signature: sign(&one_time_kyber),
        }],
    )
}

fn new_device_secrets() -> (u32, [u8; 32]) {
    let mut rng = rand::thread_rng();
    let mut credential = [0u8; 32];
    rng.fill_bytes(&mut credential);
    ((rng.next_u32() % 16383) + 1, credential)
}

impl ChatAccount {
    /// `user`'s Chat side, before it has a device: a new identity.
    pub fn of(user: &User, token: &str) -> ChatAccount {
        ChatAccount::from_keys(user.person.clone(), token, &user.identity)
    }

    /// The Chat side of the account `account` with the account keys `keys`,
    /// before it has a device: a new identity.
    pub fn from_keys(
        account: AccountRef,
        token: &str,
        keys: &AccountIdentityKeysV1,
    ) -> ChatAccount {
        ChatAccount {
            account,
            token: token.to_owned(),
            authority: keys.authority_signing_key().clone(),
            drive: AccountManifestDriveKeysV1 {
                suite: AccountIdentitySuiteId::XWingEd25519V2,
                hpke_public_key: b64(&keys.drive_hpke_public_key()),
                share_signing_public_key: b64(&keys.drive_signing_public_key()),
            },
            identity: IdentityKeyPair::generate(&mut rand09::rng()),
            devices: Vec::new(),
            head: None,
        }
    }

    pub fn identity_key(&self) -> String {
        b64(&self.identity.identity_key().serialize())
    }

    /// The account's next manifest listing `devices`, signed by its authority.
    pub fn next_manifest(&self, devices: &[&ChatDevice]) -> AccountManifestV2 {
        let public = self.authority.verifying_key();
        let mut incarnation = Sha256::new();
        incarnation.update(b"kutup/account-incarnation/v1\0");
        incarnation.update(public.as_bytes());
        let mut listed: Vec<AccountManifestDeviceV2> = devices
            .iter()
            .map(|device| AccountManifestDeviceV2 {
                device_id: device.id,
                direct_chat_suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
                registration_id: device.registration_id,
                mls: None,
            })
            .collect();
        listed.sort_by_key(|device| device.device_id);
        let mut manifest = AccountManifestV2 {
            manifest_version: 2,
            account: self.account.clone(),
            incarnation_id: hex::encode(incarnation.finalize()),
            sequence: self.head.as_ref().map_or(1, |head| head.sequence + 1),
            previous_hash: self.head.as_ref().map(|head| head.manifest_hash().unwrap()),
            identity_key: self.identity_key(),
            identity_binding: String::new(),
            drive: self.drive.clone(),
            devices: listed,
            issued_at: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
            authority_key_id: hex::encode(Sha256::digest(public.as_bytes())),
            self_authority_key: b64(public.as_bytes()),
            signature: String::new(),
        };
        self.bind(&mut manifest);
        self.sign(&mut manifest);
        manifest.verify_successor(self.head.as_ref()).unwrap();
        manifest
    }

    /// The account identity's signature over `manifest`'s authority,
    /// incarnation and account (its identity binding).
    pub fn bind(&self, manifest: &mut AccountManifestV2) {
        manifest.identity_binding = b64(&self
            .identity
            .private_key()
            .calculate_signature(
                &manifest.identity_binding_bytes().unwrap(),
                &mut rand09::rng(),
            )
            .unwrap());
    }

    /// Signs `manifest` (again) with the account's authority.
    pub fn sign(&self, manifest: &mut AccountManifestV2) {
        manifest.signature = b64(&self
            .authority
            .sign(&manifest.signing_bytes().unwrap())
            .to_bytes());
    }

    /// `POST /api/chat/manifest` of `manifest` as `by`, as it is.
    pub fn post_manifest(
        &self,
        c: &Client,
        base: &str,
        by: &ChatDevice,
        manifest: &AccountManifestV2,
    ) -> Response {
        by.auth(c.post(format!("{base}/api/chat/manifest")))
            .bearer_auth(&self.token)
            .json(manifest)
            .send()
            .unwrap()
    }

    /// A registration body for a new device of this identity.
    pub fn registration(
        &self,
        registration_id: u32,
        credential: &[u8; 32],
        registration: DeviceRegistrationV1,
    ) -> RegisterChatDeviceRequestV2 {
        let (signed, last_resort, one_time, one_time_kyber) = device_keys(&self.identity);
        RegisterChatDeviceRequestV2 {
            suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
            registration_id,
            identity_key: self.identity_key(),
            signed_pre_key: signed,
            last_resort_kyber_pre_key: last_resort,
            one_time_pre_keys: one_time,
            one_time_kyber_pre_keys: one_time_kyber,
            name: "live-test-device".into(),
            credential: URL_SAFE_NO_PAD.encode(credential),
            registration,
        }
    }

    pub fn post_registration(
        &self,
        c: &Client,
        base: &str,
        body: &RegisterChatDeviceRequestV2,
    ) -> Response {
        c.post(format!("{base}/api/chat/device"))
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .unwrap()
    }

    /// The account's first device, or a new identity for it: device 1 under
    /// a manifest listing it alone; every other device is dropped.
    pub fn reregister(&mut self, c: &Client, base: &str) -> ChatDevice {
        let (registration_id, credential) = new_device_secrets();
        self.reregister_as(c, base, registration_id, credential)
    }

    /// [`Self::reregister`] with the device's registration id and credential.
    pub fn reregister_as(
        &mut self,
        c: &Client,
        base: &str,
        registration_id: u32,
        credential: [u8; 32],
    ) -> ChatDevice {
        let device = ChatDevice {
            id: kutup_chat_proto::REREGISTRATION_DEVICE_ID,
            registration_id,
            credential,
        };
        let manifest = self.next_manifest(&[&device]);
        let body = self.registration(
            registration_id,
            &credential,
            DeviceRegistrationV1::Reregistration {
                manifest: Box::new(manifest.clone()),
            },
        );
        let r = self.post_registration(c, base, &body);
        let status = r.status();
        let answer: Value = r.json().unwrap_or_default();
        assert_eq!(status, StatusCode::OK, "re-register: {answer}");
        assert_eq!(answer["deviceId"], device.id);
        self.head = Some(manifest);
        self.devices = vec![device.clone()];
        device
    }

    /// A link token asked for by `by`.
    pub fn link_token(&self, c: &Client, base: &str, by: &ChatDevice) -> String {
        let r = by
            .auth(c.post(format!("{base}/api/chat/link-tokens")))
            .bearer_auth(&self.token)
            .send()
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "link token");
        r.json::<Value>().unwrap()["token"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// A further device, linked with a token `by` asked for, then the
    /// manifest listing every device published by `by`.
    pub fn link(&mut self, c: &Client, base: &str, by: &ChatDevice) -> ChatDevice {
        let (registration_id, credential) = new_device_secrets();
        self.link_as(c, base, by, registration_id, credential)
    }

    /// [`Self::link`] with the device's registration id and credential.
    pub fn link_as(
        &mut self,
        c: &Client,
        base: &str,
        by: &ChatDevice,
        registration_id: u32,
        credential: [u8; 32],
    ) -> ChatDevice {
        let device = self.link_unlisted_as(c, base, by, registration_id, credential);
        self.devices.push(device.clone());
        self.publish(c, base, by);
        device
    }

    /// A device registered with a link token `by` asked for and never listed
    /// (a registration interrupted before its manifest): not in
    /// `self.devices`, so the next [`Self::publish`] drops it.
    pub fn link_unlisted(&self, c: &Client, base: &str, by: &ChatDevice) -> ChatDevice {
        let (registration_id, credential) = new_device_secrets();
        self.link_unlisted_as(c, base, by, registration_id, credential)
    }

    fn link_unlisted_as(
        &self,
        c: &Client,
        base: &str,
        by: &ChatDevice,
        registration_id: u32,
        credential: [u8; 32],
    ) -> ChatDevice {
        let token = self.link_token(c, base, by);
        let body = self.registration(
            registration_id,
            &credential,
            DeviceRegistrationV1::Link { link_token: token },
        );
        let r = self.post_registration(c, base, &body);
        let status = r.status();
        let answer: Value = r.json().unwrap_or_default();
        assert_eq!(status, StatusCode::OK, "link: {answer}");
        ChatDevice {
            id: answer["deviceId"].as_u64().unwrap() as u32,
            registration_id,
            credential,
        }
    }

    /// The next manifest listing every device in `self.devices`, published
    /// by `by`.
    pub fn publish(&mut self, c: &Client, base: &str, by: &ChatDevice) -> AccountManifestV2 {
        let devices: Vec<&ChatDevice> = self.devices.iter().collect();
        let manifest = self.next_manifest(&devices);
        let r = self.post_manifest(c, base, by, &manifest);
        let status = r.status();
        let text = r.text().unwrap();
        assert_eq!(status, StatusCode::OK, "publish manifest: {text}");
        self.head = Some(manifest.clone());
        manifest
    }
}
