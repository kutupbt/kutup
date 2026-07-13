//! `kutup pub` — consume a public share link (no login required).
//! Mirrors `cmd/pub.go`.

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use clap::Subcommand;
use serde::Serialize;
use url::Url;

use crate::api::public::PublicShare;
use crate::api::{Client, FileMetadata};
use kutup_crypto::secretbox;

#[derive(Subcommand)]
pub enum PubCmd {
    /// Show metadata for a public share URL.
    Get { url: String },
    /// List files in a public share.
    Ls { url: String },
    /// Download a file from a public share.
    Download {
        url: String,
        file_id: String,
        dest: Option<String>,
    },
}

pub fn run(json: bool, cmd: &PubCmd) -> Result<()> {
    match cmd {
        PubCmd::Get { url } => get(json, url),
        PubCmd::Ls { url } => ls(json, url),
        PubCmd::Download { url, file_id, dest } => download(json, url, file_id, dest.as_deref()),
    }
}

struct PubUrl {
    server_base: String,
    token: String,
    link_key: Vec<u8>,
}

/// Parses `https://example.com/s/<token>#key=<base64>` — the web app's
/// public-share route (which `kutup share public` also emits). The Go-era
/// `/p/<token>` form is accepted too.
fn parse_pub_url(s: &str) -> Result<PubUrl> {
    let u = Url::parse(s).context("parse url")?;
    if u.host_str().is_none() {
        bail!("URL must include scheme + host");
    }
    let parts: Vec<&str> = u.path().trim_matches('/').split('/').collect();
    if parts.len() < 2 || (parts[0] != "s" && parts[0] != "p") {
        bail!("URL path must be /s/<token>");
    }
    let token = parts[1].to_string();

    let frag = u.fragment().unwrap_or("");
    let key_b64 = url::form_urlencoded::parse(frag.as_bytes())
        .find(|(k, _)| k == "key")
        .map(|(_, v)| v.into_owned())
        .ok_or_else(|| anyhow!("URL fragment missing #key=..."))?;
    let link_key = base64::engine::general_purpose::STANDARD
        .decode(&key_b64)
        .context("link key base64")?;

    Ok(PubUrl {
        server_base: u.origin().ascii_serialization(),
        token,
        link_key,
    })
}

/// Unauthenticated client pointing at the URL's own host (never forwards our token).
fn pub_client(p: &PubUrl) -> Client {
    Client::new(&p.server_base, "")
}

fn unwrap_collection_key(share: &PublicShare, link_key: &[u8]) -> Result<Vec<u8>> {
    match (
        &share.encrypted_collection_key,
        &share.encrypted_collection_key_nonce,
    ) {
        (Some(enc), Some(nonce)) => {
            secretbox::open_b64(enc, nonce, link_key).context("unwrap collection key")
        }
        _ => bail!("share has no wrapped collection key"),
    }
}

fn get(json: bool, url: &str) -> Result<()> {
    let p = parse_pub_url(url)?;
    let client = pub_client(&p);
    let share = client.get_public_share(&p.token)?;
    // Validate the link key works.
    unwrap_collection_key(&share, &p.link_key)
        .context("link key from URL fragment doesn't unwrap the share")?;

    if json {
        crate::output::print_json(&share)?;
        return Ok(());
    }
    println!("Share:    {}", share.id);
    println!("Type:     {}", share.share_type);
    println!("Target:   {}", share.target_id);
    match &share.expires_at {
        Some(e) => println!("Expires:  {e}"),
        None => println!("Expires:  (never)"),
    }
    Ok(())
}

#[derive(Serialize)]
struct FileDisplay {
    id: String,
    name: String,
    #[serde(skip_serializing_if = "is_zero")]
    size: i64,
}
fn is_zero(v: &i64) -> bool {
    *v == 0
}

fn decrypt_display(f: &crate::api::File, col_key: &[u8]) -> FileDisplay {
    let inner = || -> Result<(String, i64)> {
        let file_key = secretbox::open_b64(&f.encrypted_file_key, &f.file_key_nonce, col_key)?;
        let meta_bytes = secretbox::open_b64(&f.encrypted_metadata, &f.metadata_nonce, &file_key)?;
        let meta: FileMetadata = serde_json::from_slice(&meta_bytes)?;
        Ok((meta.name, meta.size))
    };
    match inner() {
        Ok((name, size)) => FileDisplay {
            id: f.id.clone(),
            name,
            size,
        },
        Err(_) => FileDisplay {
            id: f.id.clone(),
            name: "(undecryptable)".into(),
            size: 0,
        },
    }
}

fn ls(json: bool, url: &str) -> Result<()> {
    let p = parse_pub_url(url)?;
    let client = pub_client(&p);
    let share = client.get_public_share(&p.token)?;
    if share.share_type != "collection" {
        bail!("not a collection share (type={})", share.share_type);
    }
    let col_key = unwrap_collection_key(&share, &p.link_key)?;
    let files = client.list_public_share_files(&p.token)?;
    let out: Vec<FileDisplay> = files.iter().map(|f| decrypt_display(f, &col_key)).collect();

    if json {
        crate::output::print_json(&out)?;
        return Ok(());
    }
    if out.is_empty() {
        println!("(no files in this share)");
        return Ok(());
    }
    println!(
        "{}",
        crate::output::header(format!("{:<36}  {:>12}  NAME", "ID", "SIZE"))
    );
    for d in &out {
        println!("{:<36}  {:>12}  {}", d.id, d.size, d.name);
    }
    Ok(())
}

fn download(json: bool, url: &str, file_id: &str, dest: Option<&str>) -> Result<()> {
    let dest_dir = dest.unwrap_or(".");
    let p = parse_pub_url(url)?;
    let client = pub_client(&p);
    let share = client.get_public_share(&p.token)?;
    let col_key = unwrap_collection_key(&share, &p.link_key)?;

    let files = client.list_public_share_files(&p.token)?;
    let target = files.iter().find(|f| f.id == file_id).ok_or_else(|| {
        crate::errors::NotFound(format!("file {file_id} not found in this public share"))
    })?;

    let file_key =
        secretbox::open_b64(&target.encrypted_file_key, &target.file_key_nonce, &col_key)
            .context("decrypt file key")?;
    let meta_bytes = secretbox::open_b64(
        &target.encrypted_metadata,
        &target.metadata_nonce,
        &file_key,
    )
    .context("decrypt metadata")?;
    let meta: FileMetadata = serde_json::from_slice(&meta_bytes).unwrap_or_default();

    let dest_path = {
        let pp = Path::new(dest_dir);
        if pp.is_dir() {
            pp.join(&meta.name)
        } else {
            pp.to_path_buf()
        }
    };

    let url_res = client.public_share_download_url(&p.token, file_id)?;
    let resp = crate::api::public::fetch_presigned_stream(&url_res.url)?;
    let bar = crate::output::progress_bar(resp.content_length(), &meta.name);
    let mut out = std::fs::File::create(&dest_path).context("open dest")?;
    let written = match crate::transfer::stream_download(resp, &file_key, &mut out, |n| {
        bar.set_position(n as u64)
    }) {
        Ok(w) => w,
        Err(e) => {
            drop(out);
            let _ = std::fs::remove_file(&dest_path);
            return Err(e).context("decrypt-write");
        }
    };
    bar.finish_and_clear();

    let dest_str = dest_path.to_string_lossy().into_owned();
    if json {
        crate::output::print_json(
            &serde_json::json!({ "fileId": file_id, "size": written, "dest": dest_str }),
        )?;
    } else {
        println!("Downloaded {} → {dest_str}", meta.name);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_pub_url;
    use base64::Engine;

    #[test]
    fn parses_web_and_legacy_paths() {
        let key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        for path in ["s", "p"] {
            let u = parse_pub_url(&format!("https://h.example/{path}/tok123#key={key}")).unwrap();
            assert_eq!(u.token, "tok123");
            assert_eq!(u.server_base, "https://h.example");
            assert_eq!(u.link_key.len(), 32);
        }
        assert!(parse_pub_url("https://h.example/x/tok#key=aaaa").is_err());
        assert!(parse_pub_url("https://h.example/s/tok").is_err()); // missing #key
    }
}
