//! How a format grows without a wipe (docs/plans/format-evolution.md).
//!
//! Every sealed JSON plaintext starts with `"v"`, its format version, and may
//! carry `"min"`, the oldest reader version that can act on it safely (the
//! plan's "minimum reader" integer, decided 2026-11-12 in place of a `crit`
//! list). `min` is written only when it is below `v`; absent, it is `v`. So:
//!
//! - an additive change (a new optional field) keeps `v`: older readers keep
//!   the field in their `extra` map and write it back when they rewrite;
//! - a writer that bumps `v` for something an older reader may safely ignore
//!   writes `"min"` with the oldest version that still reads it;
//! - a breaking change bumps `v` and writes no `min`.
//!
//! A reader whose own version is below the object's minimum refuses it as
//! [`CryptoError::NewerThanMe`]: "update Kutup to open this", the bytes kept,
//! never deleted, overwritten or repaired. Everything else that fails is
//! *corrupt* (today's errors).
//!
//! Open enums are classed by [`OpenEnumClass`]; [`OPEN_ENUMS`] lists every
//! enum a format carries, and a test checks the list against the sources.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{CryptoError, Result};

/// The fields a newer writer added that this reader does not know: kept in
/// sorted order and written back unchanged on a rewrite. Flatten it into a
/// format's struct (`#[serde(flatten, default)]`), and check it with
/// [`check_extra`].
pub type Extra = BTreeMap<String, serde_json::Value>;

/// The most unknown fields a plaintext may carry. The plaintext's own size
/// limit still bounds the whole.
pub const MAX_EXTRA_FIELDS: usize = 64;

/// `v` and `min` as a reader finds them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionHeader {
    pub v: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<u16>,
}

/// Whether a reader of version `reader` may open an object of `v` and `min`.
/// `min` must be below `v` when present (no second spelling of "min = v").
/// A version 0, or a `min` that is 0 or not below `v`, is corrupt; a minimum
/// above `reader` is [`CryptoError::NewerThanMe`].
pub fn check_version(what: &str, v: u16, min: Option<u16>, reader: u16) -> Result<()> {
    if v == 0 {
        return Err(CryptoError::InvalidInput(format!("{what}: version 0")));
    }
    let minimum = match min {
        None => v,
        Some(min) if min >= 1 && min < v => min,
        Some(_) => {
            return Err(CryptoError::InvalidInput(format!(
                "{what}: min must be below v"
            )))
        }
    };
    if minimum > reader {
        return Err(newer(what));
    }
    Ok(())
}

/// The *newer than me* error for `what`.
pub fn newer(what: &str) -> CryptoError {
    CryptoError::NewerThanMe(what.to_owned())
}

/// Reads `v` and `min` from a JSON object before the format's own struct, so
/// an object from a newer writer is *newer than me* even when its fields no
/// longer fit this reader's struct.
pub fn check_json_version(what: &str, bytes: &[u8], reader: u16) -> Result<()> {
    #[derive(Deserialize)]
    struct Probe {
        v: Option<serde_json::Value>,
        min: Option<serde_json::Value>,
    }
    let probe: Probe = serde_json::from_slice(bytes)
        .map_err(|_| CryptoError::InvalidInput(format!("{what}: not a JSON object")))?;
    let number = |value: Option<serde_json::Value>, field: &str| -> Result<Option<u16>> {
        match value {
            None => Ok(None),
            Some(value) => value
                .as_u64()
                .and_then(|n| u16::try_from(n).ok())
                .map(Some)
                .ok_or_else(|| CryptoError::InvalidInput(format!("{what}: {field} is invalid"))),
        }
    };
    let v =
        number(probe.v, "v")?.ok_or_else(|| CryptoError::InvalidInput(format!("{what}: no v")))?;
    check_version(what, v, number(probe.min, "min")?, reader)
}

/// Checks the unknown fields a reader kept: how many, and that none is a
/// field the format reserves (`v`, `min` and the format's own names never
/// land here; serde takes them first).
pub fn check_extra(what: &str, extra: &Extra) -> Result<()> {
    if extra.len() > MAX_EXTRA_FIELDS {
        return Err(CryptoError::InvalidInput(format!(
            "{what}: too many unknown fields"
        )));
    }
    if extra.keys().any(|key| key.is_empty() || key.len() > 64) {
        return Err(CryptoError::InvalidInput(format!(
            "{what}: an unknown field's name is invalid"
        )));
    }
    Ok(())
}

/// What an unknown code of an open enum does to its object (rule 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenEnumClass {
    /// The unknown code is skipped alone: the item carrying it is kept and
    /// shown as unreadable, the rest of the object is read.
    Skip,
    /// The unknown code refuses the whole object as *newer than me*.
    Refuse,
}

/// Every enum a persistent or wire format carries, by its Rust path, and its
/// class. Kept in step with the sources by `every_open_enum_has_a_class`.
pub const OPEN_ENUMS: &[(&str, OpenEnumClass)] = &[
    // kutup-crypto: suites and purposes select keys and policy: *refuse*.
    ("kutup_crypto::account_record::AccountRecordSuiteId", Refuse),
    ("kutup_crypto::account_record::AccountRecordPurpose", Refuse),
    ("kutup_crypto::drive_envelope::DriveEnvelopePurpose", Refuse),
    ("kutup_crypto::drive_object::DriveObjectSuiteId", Refuse),
    ("kutup_crypto::drive_object::DriveObjectPurpose", Refuse),
    ("kutup_crypto::blocks (manifest signer kind)", Refuse),
    ("kutup_crypto::blocks (block header suite)", Refuse),
    ("kutup_crypto::local_state::LocalStateSuiteId", Refuse),
    ("kutup_crypto::local_state::LocalStatePurpose", Refuse),
    ("kutup_crypto::named_share::NamedShareSuiteId", Refuse),
    ("kutup_crypto::chat_media::ChatMediaSuiteId", Refuse),
    ("kutup_crypto::chat_media::ChatMediaObjectPurpose", Refuse),
    ("kutup_crypto::chat_backup::ChatBackupSuiteId", Refuse),
    (
        "kutup_crypto::chat_backup::ChatBackupProtectionDomainV1",
        Refuse,
    ),
    (
        "kutup_crypto::chat_backup::ChatBackupObjectPurposeV1",
        Refuse,
    ),
    ("kutup_crypto::envelope::CollabFrameSuiteId", Refuse),
    (
        "kutup_crypto::collection_epoch::CollectionEpochSuiteId",
        Refuse,
    ),
    ("kutup_crypto::chat_profile::ProfileSuiteId", Refuse),
    ("kutup_crypto::chat_profile::ProfileEnvelopePurpose", Refuse),
    // kutup-crypto: what is only shown.
    ("kutup_crypto::thumbnail::ThumbnailFormat", Skip),
    ("kutup_crypto::file_metadata::TakenFrom", Skip),
    ("kutup_crypto::mail_key (key list flags)", Skip),
    // kutup-chat-proto
    ("kutup_chat_proto::DirectChatSuiteId", Skip),
    ("kutup_chat_proto::EnvelopeType", Skip),
    ("kutup_chat_proto::AccountIdentitySuiteId", Refuse),
    (
        "kutup_chat_proto::security_policy::SealedSenderSuiteId",
        Refuse,
    ),
    ("kutup_chat_proto::media::ChatMediaClassV1", Refuse),
    (
        "kutup_chat_proto::media::ChatMediaConversationKindV1",
        Refuse,
    ),
    (
        "kutup_chat_proto::media::ChatAttachmentLedgerStateV1",
        Refuse,
    ),
    ("kutup_chat_proto::content::kind (ChatContent.kind)", Skip),
    ("kutup_chat_proto::backup (record type)", Skip),
    ("kutup_chat_proto::group (change actions)", Refuse),
];

use OpenEnumClass::{Refuse, Skip};

/// The class of `path` in [`OPEN_ENUMS`].
pub fn class_of(path: &str) -> Option<OpenEnumClass> {
    OPEN_ENUMS
        .iter()
        .find(|(name, _)| *name == path)
        .map(|(_, class)| *class)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `TryFrom<u8>` / `TryFrom<u16>` enum in the format crates has a
    /// class (rule 6): adding one without a row in [`OPEN_ENUMS`] fails here.
    #[test]
    fn every_open_enum_has_a_class() {
        let crates = [
            ("kutup_crypto", concat!(env!("CARGO_MANIFEST_DIR"), "/src")),
            (
                "kutup_chat_proto",
                concat!(env!("CARGO_MANIFEST_DIR"), "/../kutup-chat-proto/src"),
            ),
        ];
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
        let mut missing = Vec::new();
        for (krate, dir) in crates {
            let mut files = Vec::new();
            walk(std::path::Path::new(dir), &mut files);
            for file in files {
                let text = std::fs::read_to_string(&file).unwrap();
                for line in text.lines() {
                    let line = line.trim();
                    let Some(rest) = line
                        .strip_prefix("impl TryFrom<u8> for ")
                        .or_else(|| line.strip_prefix("impl TryFrom<u16> for "))
                    else {
                        continue;
                    };
                    let name = rest.trim_end_matches(" {").trim();
                    let known = OPEN_ENUMS.iter().any(|(path, _)| {
                        path.starts_with(krate) && path.ends_with(&format!("::{name}"))
                    });
                    if !known {
                        missing.push(format!("{krate}: {name} ({})", file.display()));
                    }
                }
            }
        }
        assert!(missing.is_empty(), "enums without a class: {missing:#?}");
        let mut names: Vec<_> = OPEN_ENUMS.iter().map(|(path, _)| *path).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), OPEN_ENUMS.len(), "an enum is listed twice");
        assert_eq!(
            class_of("kutup_crypto::thumbnail::ThumbnailFormat"),
            Some(Skip)
        );
    }

    #[test]
    fn versions_have_three_outcomes() {
        assert!(check_version("x", 1, None, 1).is_ok());
        assert!(check_version("x", 3, Some(1), 1).is_ok());
        assert!(check_version("x", 3, Some(2), 2).is_ok());
        assert!(matches!(
            check_version("x", 2, None, 1),
            Err(CryptoError::NewerThanMe(_))
        ));
        assert!(matches!(
            check_version("x", 3, Some(2), 1),
            Err(CryptoError::NewerThanMe(_))
        ));
        for (v, min) in [(0, None), (2, Some(2)), (2, Some(3)), (2, Some(0))] {
            assert!(matches!(
                check_version("x", v, min, 9),
                Err(CryptoError::InvalidInput(_))
            ));
        }
    }

    #[test]
    fn probes_v_before_the_struct() {
        assert!(check_json_version("x", br#"{"v":1,"a":2}"#, 1).is_ok());
        assert!(matches!(
            check_json_version("x", br#"{"v":2,"a":{"changed":true}}"#, 1),
            Err(CryptoError::NewerThanMe(_))
        ));
        assert!(check_json_version("x", br#"{"v":2,"min":1}"#, 1).is_ok());
        for corrupt in [
            &br#"{"a":1}"#[..],
            br#"{"v":"1"}"#,
            br#"{"v":70000}"#,
            br#"[1]"#,
            b"garbage",
        ] {
            assert!(matches!(
                check_json_version("x", corrupt, 1),
                Err(CryptoError::InvalidInput(_))
            ));
        }
    }
}
