//! Offline sealed-sender root and online-certificate provisioning.
//!
//! Run this binary on the offline root-key system. It never contacts Kutup or
//! a database. Secret files are created once with mode 0600 and are never
//! printed. Only the public root description and service policy go to stdout.

use std::fs::{OpenOptions, Permissions};
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use libsignal_protocol::{KeyPair, PrivateKey, ServerCertificate};
use rand09::rngs::OsRng;
use rand09::TryRngCore as _;
use sha2::{Digest as _, Sha256};

use kutup_chat_proto::{
    DirectChatSuiteId, SealedSenderRootV1, SealedSenderServerCertificateV1,
    SealedSenderServicePolicyV1, SealedSenderSuiteId,
};

const DEFAULT_SENDER_CERTIFICATE_LIFETIME: u32 = 24 * 60 * 60;
const DEFAULT_MAXIMUM_CLOCK_SKEW: u32 = 5 * 60;
const LIBSIGNAL_REVOKED_TEST_CERTIFICATE_ID: u32 = 0xDEAD_C357;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("root-generate") => root_generate(&args[1..]),
        Some("server-issue") => server_issue(&args[1..]),
        _ => anyhow::bail!(usage()),
    }
}

fn root_generate(args: &[String]) -> anyhow::Result<()> {
    if args.len() != 1 {
        anyhow::bail!(usage());
    }
    let path = Path::new(&args[0]);
    let mut rng = OsRng.unwrap_err();
    let root = KeyPair::generate(&mut rng);
    write_secret_once(path, &root.private_key.serialize())?;
    let public = root.public_key.serialize();
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "rootId": hex::encode(Sha256::digest(public.as_ref())),
            "publicKey": STANDARD.encode(public.as_ref()),
            "privateKeyFile": path,
        }))?
    );
    Ok(())
}

fn server_issue(args: &[String]) -> anyhow::Result<()> {
    let options = Options::parse(args)?;
    kutup_federation_proto::validate_server_name(&options.domain).map_err(anyhow::Error::msg)?;
    if options.certificate_id == 0
        || options.certificate_id == LIBSIGNAL_REVOKED_TEST_CERTIFICATE_ID
        || options.activates_at < 0
        || options.expires_at
            <= options.activates_at
                + i64::from(DEFAULT_SENDER_CERTIFICATE_LIFETIME)
                + i64::from(DEFAULT_MAXIMUM_CLOCK_SKEW)
    {
        anyhow::bail!("certificate id or activation/expiry window is invalid");
    }
    let root_bytes = std::fs::read(&options.root_key)
        .map_err(|error| anyhow::anyhow!("read offline root key: {error}"))?;
    if root_bytes.len() != 32 {
        anyhow::bail!("offline root key file must contain exactly 32 raw bytes");
    }
    require_secret_permissions(&options.root_key)?;
    let root_private = PrivateKey::deserialize(&root_bytes)?;
    let root_public = root_private.public_key()?;
    let root_public_bytes = root_public.serialize();
    let root_id = hex::encode(Sha256::digest(root_public_bytes.as_ref()));

    let mut rng = OsRng.unwrap_err();
    let online = KeyPair::generate(&mut rng);
    let online_secret = STANDARD.encode(online.private_key.serialize());
    write_secret_once(&options.online_key, online_secret.as_bytes())?;
    let certificate = ServerCertificate::new(
        options.certificate_id,
        online.public_key,
        &root_private,
        &mut rng,
    )?;
    if !certificate.validate(&root_public)? {
        anyhow::bail!("generated online certificate failed root validation");
    }

    let policy = SealedSenderServicePolicyV1 {
        policy_version: 1,
        canonical_domain: options.domain,
        suite: SealedSenderSuiteId::LibsignalV2DeliveryCapabilityV1,
        roots: vec![SealedSenderRootV1 {
            root_id: root_id.clone(),
            public_key: STANDARD.encode(root_public_bytes.as_ref()),
            activates_at: options.activates_at,
            revokes_at: None,
        }],
        server_certificates: vec![SealedSenderServerCertificateV1 {
            certificate_id: options.certificate_id,
            root_id,
            certificate: STANDARD.encode(certificate.serialized()?),
            activates_at: options.activates_at,
            expires_at: options.expires_at,
        }],
        sender_certificate_lifetime_seconds: DEFAULT_SENDER_CERTIFICATE_LIFETIME,
        maximum_clock_skew_seconds: DEFAULT_MAXIMUM_CLOCK_SKEW,
        direct_chat_suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
    };
    policy.validate().map_err(anyhow::Error::msg)?;
    println!("{}", serde_json::to_string_pretty(&policy)?);
    eprintln!(
        "online signer written to {}; install its exact contents as CHAT_SEALED_SENDER_ONLINE_PRIVATE_KEY",
        options.online_key.display()
    );
    Ok(())
}

struct Options {
    domain: String,
    root_key: PathBuf,
    online_key: PathBuf,
    certificate_id: u32,
    activates_at: i64,
    expires_at: i64,
}

impl Options {
    fn parse(args: &[String]) -> anyhow::Result<Self> {
        let mut domain = None;
        let mut root_key = None;
        let mut online_key = None;
        let mut certificate_id = None;
        let mut activates_at = None;
        let mut expires_at = None;
        let mut index = 0;
        while index < args.len() {
            let name = args[index].as_str();
            let value = args
                .get(index + 1)
                .ok_or_else(|| anyhow::anyhow!("missing value for {name}"))?;
            match name {
                "--domain" => domain = Some(value.clone()),
                "--root-key" => root_key = Some(PathBuf::from(value)),
                "--online-key" => online_key = Some(PathBuf::from(value)),
                "--certificate-id" => certificate_id = Some(value.parse()?),
                "--activates-at" => activates_at = Some(value.parse()?),
                "--expires-at" => expires_at = Some(value.parse()?),
                _ => anyhow::bail!("unknown argument {name}\n{}", usage()),
            }
            index += 2;
        }
        Ok(Self {
            domain: domain.ok_or_else(|| anyhow::anyhow!("--domain is required"))?,
            root_key: root_key.ok_or_else(|| anyhow::anyhow!("--root-key is required"))?,
            online_key: online_key.ok_or_else(|| anyhow::anyhow!("--online-key is required"))?,
            certificate_id: certificate_id
                .ok_or_else(|| anyhow::anyhow!("--certificate-id is required"))?,
            activates_at: activates_at
                .ok_or_else(|| anyhow::anyhow!("--activates-at is required"))?,
            expires_at: expires_at.ok_or_else(|| anyhow::anyhow!("--expires-at is required"))?,
        })
    }
}

fn write_secret_once(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("secret path has no parent"))?;
    if !parent.exists() {
        anyhow::bail!("secret parent directory does not exist");
    }
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    #[cfg(unix)]
    std::fs::set_permissions(path, Permissions::from_mode(0o600))?;
    Ok(())
}

fn require_secret_permissions(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            anyhow::bail!("offline root key permissions must not allow group/other access");
        }
    }
    Ok(())
}

fn usage() -> &'static str {
    "usage:\n  kutup-sealed-sender-provision root-generate ROOT_KEY_FILE\n  kutup-sealed-sender-provision server-issue --domain DOMAIN --root-key ROOT_KEY_FILE --online-key NEW_ONLINE_KEY_FILE --certificate-id ID --activates-at UNIX_SECONDS --expires-at UNIX_SECONDS"
}
