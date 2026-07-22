//! Independently deployable transparency cross-view auditor.
//!
//! Fetching and archival are deliberately left to the operator's hardened HTTP
//! collector. This binary accepts immutable JSON captures, runs the exact same
//! verifier as Kutup servers, and prints original signed fork evidence as JSON.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use clap::Parser;
use kutup_chat_proto::{
    audit_operator_witness_view, audit_witness_views, TransparencyForkEvidenceV1,
    TransparencySignedStatementV1, WitnessViewV1,
};

#[derive(Debug, Parser)]
#[command(name = "kutup-transparency-auditor")]
#[command(about = "Verify captured Kutup operator and witness transparency views")]
struct Args {
    /// Canonical operator federation domain.
    #[arg(long)]
    domain: String,
    /// JSON file containing one TransparencySignedStatementV1.
    #[arg(long)]
    operator: PathBuf,
    /// JSON files containing WitnessViewV1 histories (repeatable).
    #[arg(long, required = true)]
    witness: Vec<PathBuf>,
    /// Detection timestamp in Unix seconds; defaults to the current UTC time.
    #[arg(long)]
    detected_at: Option<i64>,
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("read immutable audit capture {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parse immutable audit capture {}", path.display()))
}

fn main() -> Result<()> {
    let args = Args::parse();
    let detected_at = args
        .detected_at
        .unwrap_or_else(|| time::OffsetDateTime::now_utc().unix_timestamp());
    let operator: TransparencySignedStatementV1 = read_json(&args.operator)?;
    let views: Vec<WitnessViewV1> = args
        .witness
        .iter()
        .map(|path| read_json(path))
        .collect::<Result<_>>()?;

    let mut evidence: Option<TransparencyForkEvidenceV1> = None;
    for view in &views {
        if let Some(found) = audit_operator_witness_view(&args.domain, detected_at, &operator, view)
            .map_err(anyhow::Error::msg)?
        {
            evidence = Some(found);
            break;
        }
    }
    if evidence.is_none() {
        'outer: for (index, left) in views.iter().enumerate() {
            for right in &views[index + 1..] {
                if let Some(found) = audit_witness_views(&args.domain, detected_at, left, right)
                    .map_err(anyhow::Error::msg)?
                {
                    evidence = Some(found);
                    break 'outer;
                }
            }
        }
    }

    match evidence {
        Some(evidence) => println!("{}", serde_json::to_string_pretty(&evidence)?),
        None => println!(
            "{}",
            serde_json::json!({
                "domain": args.domain,
                "detectedAt": detected_at,
                "status": "no-cryptographic-contradiction",
                "witnessViews": views.len(),
            })
        ),
    }
    Ok(())
}
