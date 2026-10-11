//! KeePassXC's own test vaults (docs/plans/pass.md, "Tests (K0)").
//!
//! Every vault in a supported format must open, be saved as KDBX 4.1 and
//! reopen with identical content, and survive a merge with itself unchanged.
//! The vaults are KeePassXC's (GPL), so they are not copied into this
//! repository: the test reads them from `KUTUP_KDBX_CORPUS`, or from the
//! `kutup-references/keepassxc` checkout beside the repository, and is
//! skipped when neither exists.

use std::path::{Path, PathBuf};

use kutup_pass::keepass::Database;
use kutup_pass::{merge, open, save, VaultKey};

/// The passwords KeePassXC's tests use for these vaults.
const PASSWORDS: [&str; 9] = [
    "a",
    "test",
    "123",
    "",
    "t",
    "masterpw",
    "I am in great pain, please help me!",
    "b",
    "\u{394}\u{f6}\u{636}",
];

/// Vaults that must not open: deliberately broken files, KDBX 2.x from
/// before 2009, and the one that needs a YubiKey.
const UNSUPPORTED: [&str; 10] = [
    "FileKeyBinary.kdbx",
    "FileKeyHashed.kdbx",
    "FileKeyHex.kdbx",
    "FileKeyXml.kdbx",
    "FileKeyXmlBrokenBase64.kdbx",
    "FileKeyXmlV2BrokenHex.kdbx",
    "Format200.kdbx",
    "YubiKeyProtectedPasswords.kdbx",
    "BrokenHeaderHash.kdbx",
    "FileKeyXmlV2HashFail.kdbx",
];

fn corpus() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("KUTUP_KDBX_CORPUS") {
        return Some(PathBuf::from(dir));
    }
    let beside = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .map(|dir| dir.join("kutup-references/keepassxc/tests/data"))
        .find(|dir| dir.is_dir());
    beside
}

fn keys(dir: &Path, name: &str) -> Vec<VaultKey> {
    let stem = name.trim_end_matches(".kdbx");
    let key_file = ["key", "keyx"]
        .iter()
        .find_map(|ext| std::fs::read(dir.join(format!("{stem}.{ext}"))).ok());
    let mut keys: Vec<VaultKey> = PASSWORDS
        .iter()
        .map(|password| VaultKey::new().with_password(password))
        .collect();
    if let Some(file) = key_file {
        keys = keys
            .into_iter()
            .map(|key| key.with_key_file(&file))
            .collect();
        keys.push(VaultKey::new().with_key_file(&file));
    }
    keys
}

fn content(db: &Database) -> Database {
    let mut db = db.clone();
    db.config = Default::default();
    db
}

#[test]
fn keepassxc_vaults_round_trip_and_merge_with_themselves() {
    let Some(dir) = corpus() else {
        eprintln!("skipped: no KeePassXC test vaults (set KUTUP_KDBX_CORPUS)");
        return;
    };
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".kdbx"))
        .collect();
    names.sort();
    let mut checked = 0;
    for name in names {
        let bytes = std::fs::read(dir.join(&name)).unwrap();
        let opened = keys(&dir, &name)
            .into_iter()
            .find_map(|key| open(&bytes, &key).ok().map(|db| (db, key)));
        let Some((db, key)) = opened else {
            assert!(UNSUPPORTED.contains(&name.as_str()), "{name} did not open");
            continue;
        };
        let reopened =
            open(&save(&db, &key).unwrap(), &key).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(
            content(&reopened),
            content(&db),
            "{name} changed in the round trip"
        );
        let (merged, report) = merge(Some(&db), &db, &db);
        assert!(
            report.is_clean() && report.updated.is_empty(),
            "{name}: {report:?}"
        );
        assert_eq!(
            content(&merged).entries,
            content(&db).entries,
            "{name} changed in a merge with itself"
        );
        save(&merged, &key).unwrap_or_else(|error| panic!("{name}: {error}"));
        checked += 1;
    }
    assert!(checked >= 20, "only {checked} vaults were checked");
}
