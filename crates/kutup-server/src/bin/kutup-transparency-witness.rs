//! Independently deployable transparency witness.
//!
//! The witness polls one log's public signed checkpoint endpoint, verifies an
//! append-only proof from its own durable pin, co-signs the exact operator
//! statement, submits that attestation, and only then advances its local state.
//! Its signing seed and state file must live outside the log-server deployment.

use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use kutup_chat_proto::{
    SubmitTransparencyWitnessRequest, TransparencyCheckpoint, TransparencyCheckpointResponse,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use url::Url;

#[derive(Debug)]
struct Config {
    target: Url,
    witness_id: String,
    signing_key: SigningKey,
    operator_key_id: String,
    operator_public_key: String,
    state_file: PathBuf,
    interval: Duration,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WitnessState {
    checkpoint: TransparencyCheckpoint,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--print-public-key"] {
        let public = signing_key()?.verifying_key();
        println!(
            "{}",
            serde_json::json!({
                "keyId": kutup_chat_proto::transparency_signing_key_id(&public),
                "publicKey": STANDARD.encode(public.as_bytes()),
            })
        );
        return Ok(());
    }
    if !args.is_empty() {
        anyhow::bail!("usage: kutup-transparency-witness [--print-public-key]");
    }
    let config = Config::load()?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()?;
    loop {
        if let Err(error) = observe_once(&client, &config).await {
            tracing::error!(%error, "transparency witness observation failed");
            if config.interval.is_zero() {
                return Err(error);
            }
        }
        if config.interval.is_zero() {
            return Ok(());
        }
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            _ = tokio::time::sleep(config.interval) => {}
        }
    }
}

impl Config {
    fn load() -> anyhow::Result<Self> {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .init();
        let target = Url::parse(&required("KUTUP_WITNESS_TARGET")?)?;
        let allow_http = optional("KUTUP_WITNESS_ALLOW_HTTP").as_deref() == Some("1");
        if target.scheme() != "https" && !(allow_http && target.scheme() == "http") {
            anyhow::bail!("KUTUP_WITNESS_TARGET must use HTTPS");
        }
        if target.cannot_be_a_base() || target.query().is_some() || target.fragment().is_some() {
            anyhow::bail!("KUTUP_WITNESS_TARGET must be an HTTP(S) base URL");
        }
        let interval = optional("KUTUP_WITNESS_INTERVAL_SECONDS")
            .map(|value| value.parse::<u64>())
            .transpose()?
            .unwrap_or(30);
        Ok(Self {
            target,
            witness_id: required("KUTUP_WITNESS_ID")?,
            signing_key: signing_key()?,
            operator_key_id: required("KUTUP_WITNESS_OPERATOR_KEY_ID")?,
            operator_public_key: required("KUTUP_WITNESS_OPERATOR_PUBLIC_KEY")?,
            state_file: PathBuf::from(required("KUTUP_WITNESS_STATE_FILE")?),
            interval: Duration::from_secs(interval),
        })
    }
}

fn signing_key() -> anyhow::Result<SigningKey> {
    let seed = STANDARD
        .decode(required("KUTUP_WITNESS_SIGNING_KEY")?)
        .map_err(|_| anyhow::anyhow!("KUTUP_WITNESS_SIGNING_KEY must be base64"))?;
    let seed: [u8; 32] = seed.try_into().map_err(|_| {
        anyhow::anyhow!("KUTUP_WITNESS_SIGNING_KEY must decode to exactly 32 bytes")
    })?;
    Ok(SigningKey::from_bytes(&seed))
}

async fn observe_once(client: &reqwest::Client, config: &Config) -> anyhow::Result<()> {
    let prior = load_state(&config.state_file)?;
    let prior_size = prior.as_ref().map_or(0, |state| state.checkpoint.tree_size);
    let checkpoint_url = config.target.join("api/chat/transparency/checkpoint")?;
    let response = client
        .get(checkpoint_url)
        .query(&[("fromTreeSize", prior_size)])
        .send()
        .await?;
    if !response.status().is_success() {
        anyhow::bail!("checkpoint endpoint returned {}", response.status());
    }
    let mut head: TransparencyCheckpointResponse = response.json().await?;
    head.verify(prior.as_ref().map(|state| &state.checkpoint))
        .map_err(anyhow::Error::msg)?;
    if head.authentication.operator_key_id != config.operator_key_id
        || head.authentication.operator_public_key != config.operator_public_key
    {
        anyhow::bail!("operator key does not match witness policy");
    }

    // Existing witness statements do not participate in the bytes signed by
    // another witness. Remove them from the submitted object for clarity.
    head.authentication.witnesses.clear();
    let attestation = kutup_chat_proto::TransparencyWitnessAttestation::sign(
        &head.authentication,
        &head.checkpoint,
        &head.map_root,
        config.witness_id.clone(),
        OffsetDateTime::now_utc().unix_timestamp(),
        &config.signing_key,
    )
    .map_err(anyhow::Error::msg)?;
    let submit_url = config.target.join("api/chat/transparency/witness")?;
    let response = client
        .post(submit_url)
        .json(&SubmitTransparencyWitnessRequest {
            tree_size: head.checkpoint.tree_size,
            attestation,
        })
        .send()
        .await?;
    if !response.status().is_success() {
        anyhow::bail!("witness submission returned {}", response.status());
    }
    store_state(
        &config.state_file,
        &WitnessState {
            checkpoint: head.checkpoint.clone(),
        },
    )?;
    tracing::info!(
        tree_size = head.checkpoint.tree_size,
        root_hash = head.checkpoint.root_hash,
        "transparency checkpoint witnessed"
    );
    Ok(())
}

fn load_state(path: &Path) -> anyhow::Result<Option<WitnessState>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn store_state(path: &Path, state: &WitnessState) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("witness state path has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let bytes = serde_json::to_vec(state)?;
    std::fs::write(&temporary, bytes)?;
    std::fs::rename(&temporary, path)?;
    Ok(())
}

fn required(name: &str) -> anyhow::Result<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("required environment variable not set: {name}"))
}

fn optional(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}
