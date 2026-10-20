//! Every 8-byte format magic (`KUTP…`) in kutup-crypto and kutup-chat-proto
//! is its own: a sealed object of one kind must never pass another kind's
//! header check. Read from the sources, so a new format with a taken magic
//! fails here instead of in review.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Pairs that share a magic from before this check, each with why the two
/// can't be mistaken for each other. A new entry needs the same reasoning,
/// and a format change should remove it instead.
const KNOWN_SHARED: &[(&str, &[&str])] = &[(
    "KUTPCE1\0",
    // A Drive collection epoch statement is a fixed-length signed record
    // read only from the collection epoch routes; a Chat attachment ledger
    // entry lives only inside the sealed ledger. Neither parser ever sees
    // the other's bytes. To be split in the next format change of either.
    &[
        "kutup-chat-proto/src/media.rs",
        "kutup-crypto/src/collection_epoch.rs",
    ],
)];

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The magic a `const` line declares, unescaped, when it is 8 bytes.
fn declared_magic(line: &str) -> Option<String> {
    if !line.contains("const ") {
        return None;
    }
    let start = line.find("b\"KUTP")? + 2;
    let end = start + line[start..].find('"')?;
    let magic = line[start..end].replace("\\0", "\0");
    (magic.len() == 8).then_some(magic)
}

#[test]
fn every_format_magic_is_its_own() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut seen: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for krate in ["kutup-crypto", "kutup-chat-proto"] {
        let mut files = Vec::new();
        sources(&crates.join(krate).join("src"), &mut files);
        for file in files {
            let text = std::fs::read_to_string(&file).unwrap();
            let name = format!(
                "{krate}/{}",
                file.strip_prefix(crates.join(krate)).unwrap().display()
            );
            for line in text.lines() {
                if let Some(magic) = declared_magic(line) {
                    seen.entry(magic).or_default().push(name.clone());
                }
            }
        }
    }
    assert!(seen.len() >= 15, "found too few magics: {seen:?}");
    for (magic, files) in &seen {
        if files.len() < 2 {
            continue;
        }
        let mut sorted = files.clone();
        sorted.sort();
        let known = KNOWN_SHARED.iter().any(|(m, f)| {
            *m == magic && f.iter().map(|s| s.to_string()).eq(sorted.iter().cloned())
        });
        assert!(
            known,
            "{magic:?} is declared by more than one format: {files:?}"
        );
    }
}
