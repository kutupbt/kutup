//! Kutup Pass in the browser (docs/plans/pass.md, K2b): a [`Vault`] holds one
//! open KeePass vault in WASM memory. The website reads its view, changes it
//! with operations (`kutup_pass::edit::Op`, as JSON objects), saves it as
//! KDBX 4.1 and merges it with another version, all with the same Rust code
//! `kutup sync` uses. Key derivation is slow on purpose: run it in a worker.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chrono::{DateTime, NaiveDateTime};
use kutup_pass::edit::{self, Op};
use kutup_pass::keepass::db::EntryId;
use kutup_pass::keepass::Database;
use kutup_pass::{view, VaultKey};
use serde::Serialize;
use wasm_bindgen::prelude::*;

fn js_error(message: impl std::fmt::Display) -> JsValue {
    JsError::new(&message.to_string()).into()
}

/// A vault that didn't open: its kind first (`wrongKey`, `unsupported`,
/// `damaged`, `keyFile`, `emptyKey`), so the page says why.
fn open_error(error: kutup_pass::kdbx::KdbxError) -> JsValue {
    js_error(format!("{}: {error}", error.kind()))
}

/// What a file is, from its header alone: `{ kind: "supported", version:
/// "4.1", upgrade }`, `{ kind: "unsupported", version }` or `{ kind:
/// "notKeePass" }`.
#[wasm_bindgen(js_name = probeVault)]
pub fn probe_vault(contents: &[u8]) -> Result<JsValue, JsValue> {
    #[derive(Serialize)]
    #[serde(tag = "kind", rename_all = "camelCase")]
    enum Probe {
        Supported { version: String, upgrade: bool },
        Unsupported { version: String },
        NotKeePass,
    }
    use kutup_pass::kdbx::VaultFormat;
    to_js(&match kutup_pass::kdbx::probe(contents) {
        VaultFormat::Supported { version, upgrade } => Probe::Supported {
            version: format!("{}.{}", version.0, version.1),
            upgrade,
        },
        VaultFormat::Unsupported { version } => Probe::Unsupported {
            version: format!("{}.{}", version.0, version.1),
        },
        VaultFormat::NotKeePass => Probe::NotKeePass,
    })
}

/// What the account keeps for vault `from` (base64), sealed for its copy `to`
/// at `revision` (base64): the copy has the same key, so it opens with the
/// sign-in too. Neither vault is opened.
#[wasm_bindgen(js_name = resealKeptKey)]
pub fn reseal_kept_key(
    envelope: &str,
    master_key: &[u8],
    binding: &str,
    from: &str,
    to: &str,
    revision: f64,
) -> Result<String, JsValue> {
    let envelope = STANDARD
        .decode(envelope)
        .map_err(|_| js_error("the kept key is not base64"))?;
    let sealed = kutup_pass::kept::reseal(
        &envelope,
        master_key,
        binding,
        &vault_id(from)?,
        &vault_id(to)?,
        revision_arg(revision)?,
    )
    .map_err(js_error)?;
    Ok(STANDARD.encode(sealed))
}

/// A new KeePassXC key file (XML v2, 32 random bytes): for the person to
/// download, never sent anywhere.
#[wasm_bindgen(js_name = generateKeyFile)]
pub fn generate_key_file() -> Result<Vec<u8>, JsValue> {
    Ok(kutup_pass::kdbx::generate_key_file().to_vec())
}

fn to_js<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    // `null`, not `undefined`, for what is missing.
    value
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(js_error)
}

fn time(unix_ms: f64) -> Result<NaiveDateTime, JsValue> {
    DateTime::from_timestamp((unix_ms / 1000.0).floor() as i64, 0)
        .map(|t| t.naive_utc())
        .ok_or_else(|| js_error("invalid time"))
}

fn key(password: Option<String>, key_file: Option<Vec<u8>>) -> Result<VaultKey, JsValue> {
    if password.is_none() && key_file.is_none() {
        return Err(js_error("a vault needs a password or a key file"));
    }
    let mut key = VaultKey::new();
    if let Some(password) = password {
        key = key.with_password(&password);
    }
    if let Some(file) = key_file {
        key = key.with_key_file(&file);
    }
    Ok(key)
}

/// What a merge did, and whether its result differs from what the other
/// side holds (then it needs saving).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MergeOutcome {
    report: kutup_pass::MergeReport,
    differs_from_theirs: bool,
    /// Theirs opened with this vault's own key (not an older one, not one
    /// given): a key change this vault holds is in Drive already.
    theirs_under_current_key: bool,
}

/// One open vault.
#[wasm_bindgen]
pub struct Vault {
    db: Database,
    key: VaultKey,
    /// The key before a change Drive does not hold yet (and when the key was
    /// last changed before): Drive's copy still opens with it, so the new
    /// key is not kept yet, and a failed save goes back to it
    /// (`abandonKeyChange`).
    previous_key: Option<(VaultKey, Option<chrono::NaiveDateTime>)>,
}

#[wasm_bindgen]
impl Vault {
    /// A new, empty vault with KeePassXC's defaults.
    pub fn create(
        name: &str,
        password: Option<String>,
        key_file: Option<Vec<u8>>,
        now_ms: f64,
    ) -> Result<Vault, JsValue> {
        let key = key(password, key_file)?;
        let db = edit::new_vault(name, time(now_ms)?).map_err(js_error)?;
        Ok(Vault {
            db,
            key,
            previous_key: None,
        })
    }

    /// Opens a vault's file contents. Fails with a wrong key or a file that
    /// is not a KeePass vault. The password may be given as its SHA-256
    /// (`password_hash`, what Kutup Pass keeps), which opens and saves the
    /// vault as the password does.
    pub fn open(
        contents: &[u8],
        password: Option<String>,
        password_hash: Option<Vec<u8>>,
        key_file: Option<Vec<u8>>,
    ) -> Result<Vault, JsValue> {
        let key = match password_hash {
            Some(hash) if password.is_none() => {
                // Wiped once used, the copy too.
                let hash = zeroize::Zeroizing::new(hash);
                let hash: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new(
                    hash.as_slice()
                        .try_into()
                        .map_err(|_| js_error("a password hash is 32 bytes"))?,
                );
                let mut key = VaultKey::new().with_password_hash(&hash);
                if let Some(file) = key_file {
                    key = key.with_key_file(&file);
                }
                key
            }
            Some(_) => return Err(js_error("give the password or its hash, not both")),
            None => key(password, key_file)?,
        };
        let db = kutup_pass::open(contents, &key).map_err(open_error)?;
        Ok(Vault {
            db,
            key,
            previous_key: None,
        })
    }

    /// The whole vault: `kutup_pass::view::VaultView`.
    pub fn view(&self) -> Result<JsValue, JsValue> {
        to_js(&view::view(&self.db))
    }

    /// Applies one operation (`kutup_pass::edit::Op` as an object, e.g.
    /// `{ op: "updateEntry", id, entry }`); returns `{ id, changed }`. A
    /// refused operation throws and changes nothing.
    pub fn apply(&mut self, op: JsValue, now_ms: f64) -> Result<JsValue, JsValue> {
        let op: Op = serde_wasm_bindgen::from_value(op).map_err(js_error)?;
        let applied = edit::apply(&mut self.db, &op, time(now_ms)?).map_err(js_error)?;
        to_js(&applied)
    }

    fn entry(&self, id: &str) -> Result<&kutup_pass::keepass::db::Entry, JsValue> {
        uuid::Uuid::parse_str(id)
            .ok()
            .and_then(|id| self.db.entries.get(&EntryId::from(id)))
            .ok_or_else(|| js_error("no such entry"))
    }

    /// An entry's earlier states, oldest first.
    pub fn history(&self, entry_id: &str) -> Result<JsValue, JsValue> {
        to_js(&view::history(&self.db, self.entry(entry_id)?))
    }

    /// The contents of an entry's attachment.
    pub fn attachment(&self, entry_id: &str, name: &str) -> Result<Vec<u8>, JsValue> {
        view::attachment(&self.db, self.entry(entry_id)?, name)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| js_error("no such attachment"))
    }

    /// The entry's one-time code now (`{ code, period, remaining }`), or
    /// `null` without a readable TOTP secret.
    pub fn otp(&self, entry_id: &str, now_ms: f64) -> Result<JsValue, JsValue> {
        let seconds = (now_ms / 1000.0).floor().max(0.0) as u64;
        to_js(&view::otp(self.entry(entry_id)?, seconds))
    }

    /// The vault as KDBX 4.1 file contents.
    pub fn save(&mut self) -> Result<Vec<u8>, JsValue> {
        // A key change is done only once Drive holds the file it saved
        // (`keyChangeSaved`); until then it can still be undone.
        kutup_pass::save(&self.db, &self.key).map_err(js_error)
    }

    /// Merges this vault (ours) with `theirs` against `base` (the version
    /// ours started from; `null` when unknown) and keeps the result here.
    /// Both open with this vault's key, or `theirs` with the key given (a
    /// key changed elsewhere, then adopted). Returns `{ report,
    /// differsFromTheirs }`.
    #[wasm_bindgen(js_name = mergeWith)]
    pub fn merge_with(
        &mut self,
        base: Option<Vec<u8>>,
        theirs: &[u8],
        theirs_password: Option<String>,
        theirs_key_file: Option<Vec<u8>>,
    ) -> Result<JsValue, JsValue> {
        let base = match base {
            // A base under an older key is merged without (KeePassXC's rules).
            Some(contents) => kutup_pass::open(&contents, &self.key).ok(),
            None => None,
        };
        // Theirs under this vault's key; or, while a key change isn't known to
        // be in Drive, under the key before it (another device saved under
        // it meanwhile): taken in, and this vault keeps its new key; or under
        // a key given (another device changed it), which this vault takes.
        let mut theirs_under_previous_key = false;
        let (theirs_db, theirs_key) = match kutup_pass::open(theirs, &self.key) {
            Ok(db) => (db, None),
            Err(error) => {
                let previous = self
                    .previous_key
                    .as_ref()
                    .and_then(|(key, _)| kutup_pass::open(theirs, key).ok());
                match previous {
                    Some(db) => {
                        theirs_under_previous_key = true;
                        (db, None)
                    }
                    None if theirs_password.is_some() || theirs_key_file.is_some() => {
                        let other = key(theirs_password, theirs_key_file)?;
                        let db = kutup_pass::open(theirs, &other).map_err(open_error)?;
                        (db, Some(other))
                    }
                    None => return Err(js_error(error)),
                }
            }
        };
        let theirs_under_current_key = !theirs_under_previous_key && theirs_key.is_none();
        let (merged, report) = kutup_pass::merge(base.as_ref(), &self.db, &theirs_db);
        let mut a = merged.clone();
        a.config = theirs_db.config.clone();
        let differs_from_theirs = a != theirs_db;
        self.db = merged;
        if let Some(key) = theirs_key {
            self.key = key;
        }
        to_js(&MergeOutcome {
            report,
            // Theirs under the old key differs whatever its entries: it must
            // be saved again, under the new one.
            differs_from_theirs: differs_from_theirs || theirs_under_previous_key,
            theirs_under_current_key,
        })
    }

    /// What the account keeps of this vault's key (docs/plans/pass.md, "Vault
    /// secrets"), sealed under the master key for `binding` and vault
    /// `file_id`: the key this vault was opened or made with, so it is known
    /// to open it. `generated`: its password is one Kutup Pass made, kept to
    /// be shown (then the key must hold the password itself, not only its
    /// hash). Base64. Fails after `changeKey` until `keyChangeSaved` (Drive's
    /// copy still opens with the old key).
    #[wasm_bindgen(js_name = keepKey)]
    pub fn keep_key(
        &self,
        master_key: &[u8],
        binding: &str,
        file_id: &str,
        revision: f64,
        generated: bool,
    ) -> Result<String, JsValue> {
        if self.previous_key.is_some() {
            return Err(js_error(
                "save the vault with its new key before keeping it",
            ));
        }
        let sealed = kutup_pass::kept::seal(
            master_key,
            binding,
            &vault_id(file_id)?,
            revision_arg(revision)?,
            // This vault's own key, never bytes from the page.
            &self.key,
            if generated {
                kutup_pass::kept::PasswordKind::Generated
            } else {
                kutup_pass::kept::PasswordKind::Chosen
            },
        )
        .map_err(js_error)?;
        Ok(STANDARD.encode(sealed))
    }

    /// Whether the kept key `envelope` (base64) is the key this vault is open
    /// with: then keeping this vault's key again is not needed. False for one
    /// that does not open here.
    #[wasm_bindgen(js_name = keptKeyIsMine)]
    pub fn kept_key_is_mine(
        &self,
        envelope: &str,
        master_key: &[u8],
        binding: &str,
        file_id: &str,
    ) -> Result<bool, JsValue> {
        let Ok(envelope) = STANDARD.decode(envelope) else {
            return Ok(false);
        };
        Ok(
            kutup_pass::kept::open(&envelope, master_key, binding, &vault_id(file_id)?)
                .is_ok_and(|kept| kept.key.same_as(&self.key)),
        )
    }

    /// Changes the vault's key: saved with the next `save`, done once Drive
    /// holds that (`keyChangeSaved`), undone with `abandonKeyChange`.
    /// `shownPassword`: with the password kept, the password Kutup Pass
    /// generated for the vault as the account keeps it (to stay one that can
    /// be shown). Used only if it is this vault's password now; otherwise
    /// the password part is kept as it is and the answer says it can't be
    /// shown (`{ passwordShowable }`), never a stale copy put in its place.
    #[wasm_bindgen(js_name = changeKey)]
    pub fn change_key(
        &mut self,
        password: Option<String>,
        keep_password: bool,
        shown_password: Option<String>,
        key_file: Option<Vec<u8>>,
        keep_key_file: bool,
        now_ms: f64,
    ) -> Result<JsValue, JsValue> {
        // What is kept comes from this vault's own key, never from the page.
        if (keep_password && password.is_some())
            || (keep_key_file && key_file.is_some())
            || (!keep_password && shown_password.is_some())
        {
            return Err(js_error(
                "keep a part of the key or give a new one, not both",
            ));
        }
        let shown = shown_password.filter(|shown| self.key.has_this_password(shown));
        let mut new = match &shown {
            Some(shown) => self.key.keeping(false, keep_key_file).with_password(shown),
            None => self.key.keeping(keep_password, keep_key_file),
        };
        if let Some(password) = password {
            new = new.with_password(&password);
        }
        if let Some(file) = key_file {
            new = new.with_key_file(&file);
        }
        new.check().map_err(js_error)?;
        let changed = Some(time(now_ms)?);
        let old = std::mem::replace(&mut self.key, new);
        // A second change before a save still goes back to the saved key.
        if self.previous_key.is_none() {
            self.previous_key = Some((old, self.db.meta.master_key_changed));
        }
        self.db.meta.master_key_changed = changed;
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Changed {
            password_showable: bool,
        }
        to_js(&Changed {
            password_showable: shown.is_some(),
        })
    }

    /// Drive holds the file saved with the new key: the change is done, and
    /// the new key can be kept.
    #[wasm_bindgen(js_name = keyChangeSaved)]
    pub fn key_change_saved(&mut self) {
        self.previous_key = None;
    }

    /// Goes back to the key the vault was saved with, after a change whose
    /// save did not reach Drive: the change is undone, never left half-made.
    #[wasm_bindgen(js_name = abandonKeyChange)]
    pub fn abandon_key_change(&mut self) {
        if let Some((key, changed)) = self.previous_key.take() {
            self.key = key;
            self.db.meta.master_key_changed = changed;
        }
    }

    /// What the vault's key is made of: `{ password, keyFile }` (a password
    /// known only as its hash, opened with a kept key, counts).
    #[wasm_bindgen(js_name = keyParts)]
    pub fn key_parts(&self) -> Result<JsValue, JsValue> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct KeyParts {
            password: bool,
            key_file: bool,
        }
        to_js(&KeyParts {
            password: self.key.has_password(),
            key_file: self.key.key_file().is_some(),
        })
    }
}

/// A revision from JavaScript: a positive safe integer (unix milliseconds).
fn revision_arg(revision: f64) -> Result<u64, JsValue> {
    if revision.fract() != 0.0 || !(1.0..=9_007_199_254_740_991.0).contains(&revision) {
        return Err(js_error("revision must be a positive safe integer"));
    }
    Ok(revision as u64)
}

fn vault_id(file_id: &str) -> Result<[u8; 16], JsValue> {
    Ok(*uuid::Uuid::parse_str(file_id)
        .map_err(|_| js_error("a vault's file id is a UUID"))?
        .as_bytes())
}

/// A kept vault key, opened, for JavaScript (bytes in base64).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KeptView {
    /// SHA-256 of the password: what opens the vault in place of it.
    password_hash: Option<String>,
    key_file: Option<String>,
    /// The password, when Kutup Pass generated it (to show).
    generated_password: Option<String>,
    /// The revision it was kept at; the next keep goes on top of it.
    revision: f64,
}

/// Opens what the account keeps for vault `fileId` (base64):
/// `{ passwordHash, keyFile, generatedPassword }`.
#[wasm_bindgen(js_name = openKept)]
pub fn open_kept(
    envelope: &str,
    master_key: &[u8],
    binding: &str,
    file_id: &str,
) -> Result<JsValue, JsValue> {
    let envelope = STANDARD
        .decode(envelope)
        .map_err(|_| js_error("a kept key is base64"))?;
    let kept = kutup_pass::kept::open(&envelope, master_key, binding, &vault_id(file_id)?)
        .map_err(js_error)?;
    to_js(&KeptView {
        password_hash: kept.key.password_hash().map(|hash| STANDARD.encode(hash)),
        key_file: kept.key.key_file().map(|file| STANDARD.encode(file)),
        generated_password: kept.generated_password.as_deref().cloned(),
        revision: kept.revision as f64,
    })
}

/// An import read but not applied: what it would make.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportPreview {
    provider: &'static str,
    provider_name: &'static str,
    count: usize,
    /// The group paths it would make, `a/b`.
    groups: Vec<String>,
    /// The first entries, to show.
    sample: Vec<ImportSample>,
    skipped: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportSample {
    title: String,
    username: String,
    url: String,
    group: String,
}

/// Why a file cannot be imported, as a code the page translates.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportFailure {
    error: &'static str,
    detail: String,
}

/// The formats an import can be read as: `[{ id, name }]`.
#[wasm_bindgen(js_name = importFormats)]
pub fn import_formats() -> Result<JsValue, JsValue> {
    #[derive(Serialize)]
    struct Format {
        id: &'static str,
        name: &'static str,
    }
    let formats: Vec<Format> = kutup_pass::import::Provider::ALL
        .iter()
        .map(|p| Format {
            id: p.id(),
            name: p.name(),
        })
        .collect();
    to_js(&formats)
}

/// Reads another password manager's export without changing any vault:
/// `ImportPreview`, or `{ error, detail }` (`empty`, `tooLarge`, `unreadable`,
/// `unknownFormat`, `missingColumns`, `tooMany`). `provider`: a format id, or
/// null to detect it.
#[wasm_bindgen(js_name = importPreview)]
pub fn import_preview(data: &[u8], provider: Option<String>) -> Result<JsValue, JsValue> {
    use kutup_pass::import::{parse, ImportError, Provider};
    let provider = match provider {
        Some(id) => Some(Provider::from_id(&id).ok_or_else(|| js_error("no such import format"))?),
        None => None,
    };
    match parse(data, provider) {
        Ok(parsed) => {
            let mut groups: Vec<String> = parsed
                .entries
                .iter()
                .filter(|e| !e.group.is_empty())
                .map(|e| e.group.join("/"))
                .collect();
            groups.sort();
            groups.dedup();
            to_js(&ImportPreview {
                provider: parsed.provider.id(),
                provider_name: parsed.provider.name(),
                count: parsed.entries.len(),
                groups,
                sample: parsed
                    .entries
                    .iter()
                    .take(50)
                    .map(|e| ImportSample {
                        title: e.title.clone(),
                        username: e.username.clone(),
                        url: e.urls.first().cloned().unwrap_or_default(),
                        group: e.group.join("/"),
                    })
                    .collect(),
                skipped: parsed.skipped,
                warnings: parsed.warnings,
            })
        }
        Err(error) => {
            let (code, detail) = match &error {
                ImportError::Empty => ("empty", String::new()),
                ImportError::TooLarge => ("tooLarge", String::new()),
                ImportError::Unreadable(why) => ("unreadable", why.clone()),
                ImportError::UnknownFormat => ("unknownFormat", String::new()),
                ImportError::MissingColumns(_, columns) => ("missingColumns", columns.clone()),
                ImportError::TooMany => ("tooMany", String::new()),
            };
            to_js(&ImportFailure {
                error: code,
                detail,
            })
        }
    }
}
