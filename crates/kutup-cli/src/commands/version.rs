//! `kutup version` — print CLI version + build info. Mirrors `cmd/version.go`.
//!
//! `version` is the Cargo package version; an optional git commit can be baked
//! in at build time via `KUTUP_GIT_COMMIT` (e.g. in CI/GoReleaser-equivalent).

pub fn run(json: bool) {
    let version = env!("CARGO_PKG_VERSION");
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let commit = option_env!("KUTUP_GIT_COMMIT");

    if json {
        let mut obj = serde_json::json!({
            "version": version,
            "os": os,
            "arch": arch,
        });
        if let Some(c) = commit {
            obj["commit"] = serde_json::Value::String(c.to_string());
        }
        println!("{obj}");
        return;
    }

    println!("kutup {version}");
    if let Some(c) = commit {
        let short = if c.len() > 12 { &c[..12] } else { c };
        println!("commit {short}");
    }
    println!("{os}/{arch}");
}
