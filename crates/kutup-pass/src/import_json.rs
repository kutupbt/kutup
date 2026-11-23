//! Exports that aren't CSV (docs/plans/pass-gaps-2.md P5): Bitwarden's
//! unencrypted JSON, Proton Pass's export (its ZIP or the `data.json` in
//! it) and 1Password's `.1pux`, read as KeePassXC's readers read them
//! (`src/format/BitwardenReader.cpp`, `ProtonPassReader.cpp`,
//! `OPUXReader.cpp`). An encrypted export is refused with its own error;
//! what a vault can't hold is reported, never dropped silently.

use chrono::{DateTime, NaiveDateTime};
use serde_json::{Map, Value};

use crate::import::{
    normalize_otp, ImportError, ImportedAttachment, ImportedEntry, Parsed, Provider,
    MAX_IMPORT_ENTRIES,
};
use crate::view::FieldView;
use crate::zip::{Zip, ZipError};

fn text<'a>(map: &'a Map<String, Value>, key: &str) -> &'a str {
    map.get(key).and_then(Value::as_str).unwrap_or("")
}

fn object<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a Map<String, Value>> {
    map.get(key).and_then(Value::as_object)
}

fn list<'a>(map: &'a Map<String, Value>, key: &str) -> &'a [Value] {
    map.get(key)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn field(key: &str, value: &str, protected: bool) -> FieldView {
    FieldView {
        key: key.to_owned(),
        value: value.to_owned(),
        protected,
    }
}

/// Adds a custom field unless its value is empty.
fn push(entry: &mut ImportedEntry, key: &str, value: &str, protected: bool) {
    if !value.is_empty() {
        entry.fields.push(field(key, value, protected));
    }
}

fn iso_time(value: &str) -> Option<NaiveDateTime> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|t| t.naive_utc())
}

fn unix_time(value: Option<&Value>) -> Option<NaiveDateTime> {
    let seconds = value.and_then(|v| v.as_i64().or_else(|| v.as_str()?.parse().ok()))?;
    DateTime::from_timestamp(seconds, 0).map(|t| t.naive_utc())
}

/// A one-time code as an `otpauth://` URI, else kept aside with a warning.
fn set_otp(entry: &mut ImportedEntry, value: &str, warnings: &mut Vec<String>) {
    if value.is_empty() {
        return;
    }
    if entry.otp.is_some() {
        push(entry, "otp (2)", value, true);
        return;
    }
    match normalize_otp(value, &entry.title) {
        Some(uri) => entry.otp = Some(uri),
        None => {
            push(entry, "TOTP (unreadable)", value, true);
            warnings.push(format!("one-time code kept as a field: {}", entry.title));
        }
    }
}

fn json(bytes: &[u8]) -> Result<Map<String, Value>, ImportError> {
    let text = std::str::from_utf8(bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes))
        .map_err(|_| ImportError::Unreadable("not UTF-8".into()))?;
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(map)) => Ok(map),
        Ok(_) => Err(ImportError::UnknownFormat),
        Err(error) => Err(ImportError::Unreadable(error.to_string())),
    }
}

fn zip_error(error: ZipError) -> ImportError {
    match error {
        ZipError::Encrypted => ImportError::Encrypted,
        ZipError::TooLarge => ImportError::TooLarge,
        ZipError::Unreadable(why) => ImportError::Unreadable(why.into()),
    }
}

/// Which of these formats `bytes` are, if any.
pub(crate) fn detect(bytes: &[u8]) -> Option<Provider> {
    if crate::zip::is_zip(bytes) {
        let archive = Zip::open(bytes).ok()?;
        if archive.find("export.data").is_some() {
            return Some(Provider::OnePassword1pux);
        }
        if archive
            .entries
            .iter()
            .any(|e| e.name.ends_with("data.json") || e.name.ends_with("data.pgp"))
        {
            return Some(Provider::ProtonPassExport);
        }
        return None;
    }
    let start = bytes
        .strip_prefix(b"\xEF\xBB\xBF")
        .unwrap_or(bytes)
        .iter()
        .find(|b| !b.is_ascii_whitespace())?;
    if *start != b'{' {
        return None;
    }
    let map = json(bytes).ok()?;
    if map.contains_key("vaults") && map.contains_key("version") {
        Some(Provider::ProtonPassExport)
    } else if map.contains_key("items") || map.contains_key("encKeyValidation_DO_NOT_EDIT") {
        Some(Provider::BitwardenJson)
    } else {
        None
    }
}

/// Reads `bytes` as `provider`, one of this module's formats.
pub(crate) fn parse(bytes: &[u8], provider: Provider) -> Result<Parsed, ImportError> {
    let mut parsed = Parsed {
        provider,
        entries: Vec::new(),
        skipped: Vec::new(),
        warnings: Vec::new(),
    };
    match provider {
        Provider::BitwardenJson => bitwarden(&json(bytes)?, &mut parsed)?,
        Provider::ProtonPassExport => {
            if crate::zip::is_zip(bytes) {
                let mut archive = Zip::open(bytes).map_err(zip_error)?;
                if archive.entries.iter().any(|e| e.name.ends_with("data.pgp")) {
                    return Err(ImportError::Encrypted);
                }
                let data = archive
                    .entries
                    .iter()
                    .find(|e| e.name.ends_with("data.json"))
                    .cloned()
                    .ok_or(ImportError::UnknownFormat)?;
                let contents = archive.read(&data).map_err(zip_error)?;
                proton(&json(&contents)?, &mut parsed)?;
            } else {
                proton(&json(bytes)?, &mut parsed)?;
            }
        }
        Provider::OnePassword1pux => {
            if !crate::zip::is_zip(bytes) {
                return Err(ImportError::UnknownFormat);
            }
            let mut archive = Zip::open(bytes).map_err(zip_error)?;
            let data = archive
                .find("export.data")
                .cloned()
                .ok_or(ImportError::UnknownFormat)?;
            let contents = archive.read(&data).map_err(zip_error)?;
            one_pux(&json(&contents)?, &mut archive, &mut parsed)?;
        }
        _ => return Err(ImportError::UnknownFormat),
    }
    if parsed.entries.len() > MAX_IMPORT_ENTRIES {
        return Err(ImportError::TooMany);
    }
    if parsed.entries.is_empty() && parsed.skipped.is_empty() {
        return Err(ImportError::Empty);
    }
    Ok(parsed)
}

// ------------------------------------------------------------------ Bitwarden

fn bitwarden(root: &Map<String, Value>, parsed: &mut Parsed) -> Result<(), ImportError> {
    if root.get("encrypted").and_then(Value::as_bool) == Some(true)
        || root.contains_key("encKeyValidation_DO_NOT_EDIT")
    {
        return Err(ImportError::Encrypted);
    }
    // Personal vaults have folders; organization exports have collections.
    let folders: Vec<(String, String)> = list(root, "folders")
        .iter()
        .chain(list(root, "collections"))
        .filter_map(Value::as_object)
        .map(|f| (text(f, "id").to_owned(), text(f, "name").to_owned()))
        .collect();
    for item in list(root, "items").iter().filter_map(Value::as_object) {
        let mut entry = ImportedEntry {
            title: text(item, "name").to_owned(),
            notes: text(item, "notes").to_owned(),
            ..ImportedEntry::default()
        };
        let folder = item
            .get("folderId")
            .and_then(Value::as_str)
            .or_else(|| list(item, "collectionIds").first().and_then(Value::as_str));
        if let Some((_, name)) = folder.and_then(|id| folders.iter().find(|(f, _)| f == id)) {
            entry.group = name
                .split('/')
                .filter(|p| !p.is_empty())
                .map(str::to_owned)
                .collect();
        }
        if item.get("favorite").and_then(Value::as_bool) == Some(true) {
            entry.tags.push("Favorite".into());
        }
        if let Some(login) = object(item, "login") {
            entry.username = text(login, "username").to_owned();
            entry.password = text(login, "password").to_owned();
            entry.urls = list(login, "uris")
                .iter()
                .filter_map(|u| u.as_object())
                .map(|u| text(u, "uri").to_owned())
                .filter(|u| !u.is_empty())
                .collect();
            let totp = text(login, "totp").to_owned();
            set_otp(&mut entry, &totp, &mut parsed.warnings);
            if !list(login, "fido2Credentials").is_empty() {
                parsed
                    .warnings
                    .push(format!("passkey not imported: {}", entry.title));
            }
        }
        if let Some(card) = object(item, "card") {
            for key in [
                "cardholderName",
                "brand",
                "number",
                "expMonth",
                "expYear",
                "code",
            ] {
                let value = text(card, key).to_owned();
                push(
                    &mut entry,
                    &format!("card_{key}"),
                    &value,
                    key == "code" || key == "number",
                );
            }
        }
        if let Some(identity) = object(item, "identity") {
            let name: Vec<&str> = ["title", "firstName", "middleName", "lastName"]
                .iter()
                .map(|k| text(identity, k))
                .filter(|v| !v.is_empty())
                .collect();
            push(&mut entry, "identity_name", &name.join(" "), false);
            let lines: Vec<&str> = ["address1", "address2", "address3"]
                .iter()
                .map(|k| text(identity, k))
                .filter(|v| !v.is_empty())
                .collect();
            let place = format!(
                "{}, {} {}\n{}",
                text(identity, "city"),
                text(identity, "state"),
                text(identity, "postalCode"),
                text(identity, "country")
            );
            let address = format!("{}\n{}", lines.join("\n"), place);
            if address
                .trim_matches(|c: char| c == ',' || c.is_whitespace())
                .is_empty()
            {
                // Nothing in it.
            } else {
                push(&mut entry, "identity_address", address.trim(), false);
            }
            for key in [
                "company",
                "email",
                "phone",
                "ssn",
                "passportNumber",
                "licenseNumber",
            ] {
                let value = text(identity, key).to_owned();
                push(
                    &mut entry,
                    &format!("identity_{key}"),
                    &value,
                    matches!(key, "ssn" | "passportNumber" | "licenseNumber"),
                );
            }
            let user = text(identity, "username").to_owned();
            if entry.username.is_empty() {
                entry.username = user;
            } else {
                push(&mut entry, "identity_username", &user, false);
            }
        }
        if let Some(ssh) = object(item, "sshKey") {
            let (private, public) = (
                text(ssh, "privateKey").to_owned(),
                text(ssh, "publicKey").to_owned(),
            );
            push(&mut entry, "ssh_private_key", &private, true);
            push(&mut entry, "ssh_public_key", &public, false);
        }
        for f in list(item, "fields").iter().filter_map(Value::as_object) {
            let name = match text(f, "name") {
                "" => "Field",
                name => name,
            };
            // Type 1 is hidden; 3 is linked to another field (kept as written).
            let value = match f.get("value") {
                Some(Value::String(s)) => s.clone(),
                Some(Value::Null) | None => String::new(),
                Some(other) => other.to_string(),
            };
            let hidden = f.get("type").and_then(Value::as_i64) == Some(1);
            entry.fields.push(field(name, &value, hidden));
        }
        let history = list(item, "passwordHistory").len();
        if history > 0 {
            parsed.warnings.push(format!(
                "{history} earlier password(s) not imported: {}",
                entry.title
            ));
        }
        if !list(item, "attachments").is_empty() {
            parsed.warnings.push(format!(
                "attachments are not in Bitwarden's export: {}",
                entry.title
            ));
        }
        entry.created = iso_time(text(item, "creationDate"));
        entry.modified = iso_time(text(item, "revisionDate"));
        if entry.title.is_empty() {
            entry.title = crate::import::hostname(entry.urls.first().map_or("", String::as_str))
                .unwrap_or_default();
        }
        if item.get("deletedDate").is_some_and(|d| !d.is_null()) {
            parsed
                .skipped
                .push(format!("in Bitwarden's trash: {}", entry.title));
            continue;
        }
        parsed.entries.push(entry);
    }
    Ok(())
}

// ---------------------------------------------------------------- Proton Pass

fn proton(root: &Map<String, Value>, parsed: &mut Parsed) -> Result<(), ImportError> {
    if root.get("encrypted").and_then(Value::as_bool) == Some(true) {
        return Err(ImportError::Encrypted);
    }
    let vaults = object(root, "vaults").ok_or(ImportError::UnknownFormat)?;
    for vault in vaults.values().filter_map(Value::as_object) {
        let group = text(vault, "name").to_owned();
        for item in list(vault, "items").iter().filter_map(Value::as_object) {
            let Some(data) = object(item, "data") else {
                continue;
            };
            let metadata = object(data, "metadata");
            let mut entry = ImportedEntry {
                group: vec![group.clone()]
                    .into_iter()
                    .filter(|g| !g.is_empty())
                    .collect(),
                title: metadata.map_or("", |m| text(m, "name")).to_owned(),
                notes: metadata.map_or("", |m| text(m, "note")).to_owned(),
                ..ImportedEntry::default()
            };
            if item.get("pinned").and_then(Value::as_bool) == Some(true) {
                entry.tags.push("Favorite".into());
            }
            let empty = Map::new();
            let content = object(data, "content").unwrap_or(&empty);
            match text(data, "type") {
                "login" => {
                    entry.username = text(content, "itemUsername").to_owned();
                    entry.password = text(content, "password").to_owned();
                    let email = text(content, "itemEmail").to_owned();
                    if entry.username.is_empty() {
                        entry.username = email;
                    } else {
                        push(&mut entry, "login_email", &email, false);
                    }
                    entry.urls = list(content, "urls")
                        .iter()
                        .filter_map(Value::as_str)
                        .filter(|u| !u.is_empty())
                        .map(str::to_owned)
                        .collect();
                    let totp = text(content, "totpUri").to_owned();
                    set_otp(&mut entry, &totp, &mut parsed.warnings);
                    if !list(content, "passkeys").is_empty() {
                        parsed
                            .warnings
                            .push(format!("passkey not imported: {}", entry.title));
                    }
                }
                "creditCard" => {
                    entry.username = text(content, "number").to_owned();
                    entry.password = text(content, "verificationNumber").to_owned();
                    for key in ["cardholderName", "expirationDate", "pin"] {
                        let value = text(content, key).to_owned();
                        push(&mut entry, &format!("card_{key}"), &value, key == "pin");
                    }
                }
                "wifi" => {
                    entry.username = text(content, "ssid").to_owned();
                    entry.password = text(content, "password").to_owned();
                    let security = content.get("security").map(|v| match v {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    });
                    push(
                        &mut entry,
                        "wifi_security",
                        security.as_deref().unwrap_or(""),
                        false,
                    );
                }
                "sshKey" => {
                    let (public, private) = (
                        text(content, "publicKey").to_owned(),
                        text(content, "privateKey").to_owned(),
                    );
                    push(&mut entry, "ssh_public_key", &public, false);
                    push(&mut entry, "ssh_private_key", &private, true);
                }
                "alias" => {
                    entry.username = text(item, "aliasEmail").to_owned();
                    parsed.warnings.push(format!(
                        "an alias is kept as an entry; the alias itself stays with Proton: {}",
                        entry.title
                    ));
                }
                "note" => {}
                other => {
                    // Identity and custom items: every content value as a field.
                    for (key, value) in content {
                        if let Some(value) = value.as_str() {
                            push(&mut entry, &format!("content_{key}"), value, false);
                        }
                    }
                    if other.is_empty() {
                        parsed
                            .warnings
                            .push(format!("an item of no type: {}", entry.title));
                    }
                }
            }
            for f in list(data, "extraFields")
                .iter()
                .filter_map(Value::as_object)
            {
                let name = match text(f, "fieldName") {
                    "" => "Field",
                    name => name,
                };
                let kind = text(f, "type");
                let value = object(f, "data").map_or("", |d| {
                    if kind.eq_ignore_ascii_case("totp") {
                        text(d, "totpUri")
                    } else {
                        text(d, "content")
                    }
                });
                if kind.eq_ignore_ascii_case("totp") && entry.otp.is_none() {
                    let value = value.to_owned();
                    set_otp(&mut entry, &value, &mut parsed.warnings);
                } else {
                    let hidden =
                        kind.eq_ignore_ascii_case("hidden") || kind.eq_ignore_ascii_case("totp");
                    entry.fields.push(field(name, value, hidden));
                }
            }
            entry.created = unix_time(item.get("createTime"));
            entry.modified = unix_time(item.get("modifyTime"));
            if item.get("state").and_then(Value::as_i64) == Some(2) {
                parsed
                    .skipped
                    .push(format!("in Proton Pass's trash: {}", entry.title));
                continue;
            }
            parsed.entries.push(entry);
        }
    }
    Ok(())
}

// ------------------------------------------------------------------ 1Password

fn one_pux(
    root: &Map<String, Value>,
    archive: &mut Zip<'_>,
    parsed: &mut Parsed,
) -> Result<(), ImportError> {
    let accounts = list(root, "accounts");
    if accounts.is_empty() {
        return Err(ImportError::UnknownFormat);
    }
    for account in accounts.iter().filter_map(Value::as_object) {
        for vault in list(account, "vaults").iter().filter_map(Value::as_object) {
            let group = object(vault, "attrs")
                .map_or("", |a| text(a, "name"))
                .to_owned();
            for item in list(vault, "items").iter().filter_map(Value::as_object) {
                let empty = Map::new();
                let overview = object(item, "overview").unwrap_or(&empty);
                let details = object(item, "details").unwrap_or(&empty);
                let mut entry = ImportedEntry {
                    group: vec![group.clone()]
                        .into_iter()
                        .filter(|g| !g.is_empty())
                        .collect(),
                    title: text(overview, "title").to_owned(),
                    notes: text(details, "notesPlain").to_owned(),
                    tags: list(overview, "tags")
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect(),
                    ..ImportedEntry::default()
                };
                let url = text(overview, "url");
                if !url.is_empty() {
                    entry.urls.push(url.to_owned());
                }
                for u in list(overview, "urls").iter().filter_map(Value::as_object) {
                    let u = text(u, "url");
                    if !u.is_empty() && !entry.urls.iter().any(|x| x == u) {
                        entry.urls.push(u.to_owned());
                    }
                }
                if item
                    .get("favIndex")
                    .and_then(|v| v.as_i64().or_else(|| v.as_str()?.parse().ok()))
                    == Some(1)
                {
                    entry.tags.push("Favorite".into());
                }
                if text(item, "state") == "archived" {
                    entry.tags.push("Archived".into());
                }
                for f in list(details, "loginFields")
                    .iter()
                    .filter_map(Value::as_object)
                {
                    match text(f, "designation").to_ascii_lowercase().as_str() {
                        "username" => entry.username = text(f, "value").to_owned(),
                        "password" => entry.password = text(f, "value").to_owned(),
                        _ => {}
                    }
                }
                if entry.password.is_empty() {
                    entry.password = text(details, "password").to_owned();
                }
                for section in list(details, "sections")
                    .iter()
                    .filter_map(Value::as_object)
                {
                    let prefix = text(section, "title");
                    for f in list(section, "fields").iter().filter_map(Value::as_object) {
                        let mut name = text(f, "title").to_owned();
                        if name.is_empty() {
                            name = text(f, "id").to_owned();
                        }
                        if !prefix.is_empty() {
                            name = format!("{prefix}_{name}");
                        }
                        let Some((kind, value)) = object(f, "value").and_then(|v| v.iter().next())
                        else {
                            continue;
                        };
                        match kind.as_str() {
                            "totp" => {
                                let value = value.as_str().unwrap_or("").to_owned();
                                set_otp(&mut entry, &value, &mut parsed.warnings);
                            }
                            "file" => {
                                let file = value.as_object().unwrap_or(&empty);
                                attach(
                                    archive,
                                    &mut entry,
                                    text(file, "documentId"),
                                    text(file, "fileName"),
                                    parsed,
                                )?;
                            }
                            _ => {
                                let shown = match (kind.as_str(), value) {
                                    ("date" | "monthYear", v) => unix_time(Some(v))
                                        .map(crate::view::format_time)
                                        .unwrap_or_else(|| v.to_string()),
                                    ("email", Value::Object(e)) => {
                                        text(e, "email_address").to_owned()
                                    }
                                    ("address", Value::Object(a)) => format!(
                                        "{}\n{}, {} {}\n{}",
                                        text(a, "street"),
                                        text(a, "city"),
                                        text(a, "state"),
                                        text(a, "zip"),
                                        text(a, "country")
                                    ),
                                    (_, Value::String(s)) => s.clone(),
                                    (_, Value::Null) => String::new(),
                                    (_, other) => other.to_string(),
                                };
                                push(&mut entry, &name, &shown, kind == "concealed");
                            }
                        }
                    }
                }
                if let Some(document) = object(details, "documentAttributes") {
                    attach(
                        archive,
                        &mut entry,
                        text(document, "documentId"),
                        text(document, "fileName"),
                        parsed,
                    )?;
                }
                entry.created = unix_time(item.get("createdAt"));
                entry.modified = unix_time(item.get("updatedAt"));
                if text(item, "state") == "deleted" {
                    parsed
                        .skipped
                        .push(format!("in 1Password's trash: {}", entry.title));
                    continue;
                }
                parsed.entries.push(entry);
            }
        }
    }
    Ok(())
}

/// A 1PUX file (`files/<documentId>__<fileName>`) as an attachment.
fn attach(
    archive: &mut Zip<'_>,
    entry: &mut ImportedEntry,
    document: &str,
    name: &str,
    parsed: &mut Parsed,
) -> Result<(), ImportError> {
    let path = format!("files/{document}__{name}");
    match archive.find(&path).cloned() {
        Some(file) => {
            let data = archive.read(&file).map_err(zip_error)?;
            if data.len() > crate::edit::MAX_ATTACHMENT_BYTES {
                parsed.warnings.push(format!(
                    "attachment larger than 50 MiB not imported: {} ({name})",
                    entry.title
                ));
            } else {
                entry.attachments.push(ImportedAttachment {
                    name: name.to_owned(),
                    data,
                });
            }
        }
        None => parsed.warnings.push(format!(
            "attachment missing from the export: {} ({name})",
            entry.title
        )),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::parse;

    #[test]
    fn bitwarden_json_reads_logins_cards_identities_and_folders() {
        let file = r#"{
          "encrypted": false,
          "folders": [{"id": "f1", "name": "Is/Sunucular"}],
          "items": [
            {"type": 1, "name": "Banka", "notes": "n", "favorite": true, "folderId": "f1",
             "login": {"username": "ayse", "password": "p", "totp": "JBSWY3DPEHPK3PXP",
                       "uris": [{"uri": "https://a.example"}, {"uri": "https://b.example"}]},
             "fields": [{"name": "PIN", "value": "1234", "type": 1}, {"name": "On", "value": true, "type": 2}],
             "passwordHistory": [{"password": "old"}],
             "creationDate": "2024-01-02T03:04:05.000Z", "revisionDate": "2025-01-02T03:04:05.000Z"},
            {"type": 3, "name": "Kart", "card": {"cardholderName": "A", "number": "4111", "code": "123"}},
            {"type": 4, "name": "Kimlik", "identity": {"firstName": "Ayşe", "lastName": "Y", "ssn": "1", "username": "ay"}},
            {"type": 2, "name": "Silinen", "deletedDate": "2025-01-01T00:00:00Z"}
          ]
        }"#;
        let parsed = parse(file.as_bytes(), None).unwrap();
        assert_eq!(parsed.provider, Provider::BitwardenJson);
        assert_eq!(parsed.entries.len(), 3);
        let bank = &parsed.entries[0];
        assert_eq!(bank.group, ["Is", "Sunucular"]);
        assert_eq!(
            (bank.username.as_str(), bank.password.as_str()),
            ("ayse", "p")
        );
        assert_eq!(bank.urls.len(), 2);
        assert!(bank.otp.as_deref().unwrap().starts_with("otpauth://totp/"));
        assert_eq!(bank.tags, ["Favorite"]);
        assert!(bank
            .fields
            .iter()
            .any(|f| f.key == "PIN" && f.protected && f.value == "1234"));
        assert!(bank
            .fields
            .iter()
            .any(|f| f.key == "On" && f.value == "true"));
        assert_eq!(bank.created.unwrap().to_string(), "2024-01-02 03:04:05");
        let card = &parsed.entries[1];
        assert!(card
            .fields
            .iter()
            .any(|f| f.key == "card_code" && f.protected));
        let id = &parsed.entries[2];
        assert_eq!(id.username, "ay");
        assert!(id
            .fields
            .iter()
            .any(|f| f.key == "identity_name" && f.value == "Ayşe Y"));
        assert!(id
            .fields
            .iter()
            .any(|f| f.key == "identity_ssn" && f.protected));
        assert_eq!(parsed.skipped.len(), 1);
        assert!(parsed
            .warnings
            .iter()
            .any(|w| w.contains("earlier password")));
    }

    #[test]
    fn encrypted_exports_are_refused() {
        let bitwarden = br#"{"encrypted": true, "passwordProtected": true, "data": "x"}"#;
        assert_eq!(
            parse(bitwarden, Some(Provider::BitwardenJson)),
            Err(ImportError::Encrypted)
        );
        let account = br#"{"encrypted": true, "encKeyValidation_DO_NOT_EDIT": "x", "data": "y"}"#;
        assert_eq!(parse(account, None), Err(ImportError::Encrypted));
        let proton = crate::zip::tests::make(&[("Proton Pass/data.pgp", b"-----BEGIN PGP", true)]);
        assert_eq!(parse(&proton, None), Err(ImportError::Encrypted));
    }

    fn proton_json() -> Vec<u8> {
        r#"{"version": "1.21.0", "userId": "u", "encrypted": false, "vaults": {"v1": {
          "name": "Kişisel", "description": "",
          "items": [
            {"itemId": "a", "state": 1, "pinned": true, "createTime": 1700000000, "modifyTime": 1700000100,
             "data": {"type": "login", "metadata": {"name": "Posta", "note": "not"},
                      "content": {"itemEmail": "ayse@kutup.dev", "itemUsername": "", "password": "p",
                                  "urls": ["https://mail.example"], "totpUri": "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"},
                      "extraFields": [{"fieldName": "Gizli", "type": "hidden", "data": {"content": "s"}}]}},
            {"itemId": "b", "state": 1, "aliasEmail": "x.y@passmail.net",
             "data": {"type": "alias", "metadata": {"name": "Alias"}, "content": {}, "extraFields": []}},
            {"itemId": "c", "state": 2,
             "data": {"type": "note", "metadata": {"name": "Çöp"}, "content": {}, "extraFields": []}}
          ]}}}"#
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn proton_pass_reads_its_json_and_its_zip() {
        for file in [
            proton_json(),
            crate::zip::tests::make(&[("Proton Pass/data.json", &proton_json(), true)]),
        ] {
            let parsed = parse(&file, None).unwrap();
            assert_eq!(parsed.provider, Provider::ProtonPassExport);
            assert_eq!(parsed.entries.len(), 2);
            let mail = &parsed.entries[0];
            assert_eq!(mail.group, ["Kişisel"]);
            assert_eq!(mail.username, "ayse@kutup.dev");
            assert_eq!(mail.urls, ["https://mail.example"]);
            assert!(mail.otp.is_some());
            assert!(mail.fields.iter().any(|f| f.key == "Gizli" && f.protected));
            assert_eq!(mail.tags, ["Favorite"]);
            assert_eq!(parsed.entries[1].username, "x.y@passmail.net");
            assert_eq!(parsed.skipped.len(), 1);
            assert!(parsed.warnings.iter().any(|w| w.contains("alias")));
        }
    }

    #[test]
    fn one_pux_reads_logins_sections_and_files() {
        let data = br#"{"accounts": [{"attrs": {}, "vaults": [{"attrs": {"name": "Private"}, "items": [
          {"state": "active", "favIndex": 1, "createdAt": 1700000000, "updatedAt": 1700000100,
           "overview": {"title": "GitHub", "url": "https://github.com", "tags": ["dev"],
                        "urls": [{"url": "https://github.com"}, {"url": "https://gist.github.com"}]},
           "details": {"notesPlain": "n",
             "loginFields": [{"designation": "username", "value": "ayse"}, {"designation": "password", "value": "p"}],
             "sections": [{"title": "", "fields": [
                {"title": "one-time password", "id": "x", "value": {"totp": "otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP"}},
                {"title": "PIN", "id": "y", "value": {"concealed": "9999"}},
                {"title": "key", "id": "z", "value": {"file": {"fileName": "id.pub", "documentId": "d1"}}}]}]}},
          {"state": "archived", "overview": {"title": "Old"}, "details": {"loginFields": [], "sections": []}}
        ]}]}]}"#;
        let pux = crate::zip::tests::make(&[
            ("export.attributes", b"{}", false),
            ("export.data", data, true),
            ("files/d1__id.pub", b"ssh-ed25519 AAAA", true),
        ]);
        let parsed = parse(&pux, None).unwrap();
        assert_eq!(parsed.provider, Provider::OnePassword1pux);
        let gh = &parsed.entries[0];
        assert_eq!(gh.group, ["Private"]);
        assert_eq!((gh.username.as_str(), gh.password.as_str()), ("ayse", "p"));
        assert_eq!(gh.urls, ["https://github.com", "https://gist.github.com"]);
        assert!(gh.otp.is_some());
        assert!(gh.fields.iter().any(|f| f.key == "PIN" && f.protected));
        assert_eq!(gh.attachments.len(), 1);
        assert_eq!(gh.attachments[0].data, b"ssh-ed25519 AAAA");
        assert_eq!(gh.tags, ["dev", "Favorite"]);
        assert_eq!(parsed.entries[1].tags, ["Archived"]);

        // Through the vault's import: the file becomes an attachment.
        use base64::Engine as _;
        let now = chrono::NaiveDate::from_ymd_opt(2026, 11, 17)
            .unwrap()
            .and_hms_opt(9, 0, 0)
            .unwrap();
        let mut db = crate::edit::new_vault("V", now).unwrap();
        let op = crate::edit::Op::ImportCsv {
            data: base64::engine::general_purpose::STANDARD.encode(&pux),
            provider: None,
            group_name: "1Password".into(),
        };
        crate::edit::apply(&mut db, &op, now).unwrap();
        let view = crate::view::view(&db);
        let gh = view
            .entries
            .iter()
            .find(|e| {
                e.fields
                    .iter()
                    .any(|f| f.key == "Title" && f.value == "GitHub")
            })
            .unwrap();
        assert_eq!(gh.attachments.len(), 1);
        let entry =
            &db.entries[&keepass::db::EntryId::from(uuid::Uuid::parse_str(&gh.id).unwrap())];
        assert_eq!(
            crate::view::attachment(&db, entry, "id.pub"),
            Some(&b"ssh-ed25519 AAAA"[..])
        );
    }
}
