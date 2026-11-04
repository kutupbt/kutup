//! Revisions of sealed values the account replaces over time (contact cards,
//! mail folder, label and filter names, identity pins): each carries its
//! revision in its authenticated header, a time in unix milliseconds above
//! every revision its writer has seen. The server reads it from the sealed
//! value (never from a second field) and stores a new one only on top of the
//! revision the writer started from (`baseRevision`), so two devices editing
//! at once cannot silently overwrite each other: the second gets a `409`
//! with `code: "revision_conflict"` and the current revision, reads again and
//! retries.

use serde_json::json;

use crate::error::{AppError, AppResult};

/// The highest revision taken: the largest integer JavaScript holds exactly
/// (unix milliseconds stay far below it). A higher one could only be a
/// garbage value meant to stop every later write.
pub const MAX_REVISION: u64 = (1 << 53) - 1;

/// A header revision as the database stores it.
pub fn stored(revision: u64) -> AppResult<i64> {
    if revision == 0 || revision > MAX_REVISION {
        return Err(AppError::bad_request("the revision is out of range"));
    }
    Ok(revision as i64)
}

/// Checks that `new` (from the sealed value's header) follows `base` (the
/// revision the writer started from; 0 for a new value).
pub fn check_follows(new: u64, base: i64) -> AppResult<i64> {
    let new = stored(new)?;
    if base < 0 || new <= base {
        return Err(AppError::bad_request(
            "the new revision must be above the one the edit started from",
        ));
    }
    Ok(new)
}

/// The answer when another write came first: the current revision, so the
/// writer can read it and try again.
pub fn conflict(message: &'static str, current: i64) -> AppError {
    AppError::conflict(message)
        .with_details(json!({ "code": "revision_conflict", "revision": current }))
}

/// The revision of a stored sealed mail folder, label or filter name
/// (base64), as its header carries it; refuses anything else. A new name is
/// checked whole by [`new_mail_name`] before it is stored.
pub fn mail_name(sealed_b64: &str) -> AppResult<u64> {
    use kutup_crypto::account_record::{self, AccountRecordPurpose};
    let bytes = account_record::decode_record_b64(sealed_b64, AccountRecordPurpose::MailName)
        .map_err(|_| AppError::bad_request("name is not a sealed mail name"))?;
    let header = account_record::inspect(&bytes)
        .ok()
        .filter(|header| header.purpose == AccountRecordPurpose::MailName)
        .ok_or_else(|| AppError::bad_request("name is not a sealed mail name"))?;
    let revision = header
        .revision
        .ok_or_else(|| AppError::bad_request("name is not a sealed mail name"))?;
    stored(revision)?;
    Ok(revision)
}

/// A new sealed name (base64) for the `kind` with `id` of the account bound
/// by `binding`: its revision, or a refusal (another account's, kind's or
/// id's name, or not a name).
pub fn new_mail_name(
    sealed_b64: &str,
    binding: &str,
    kind: kutup_crypto::mail_names::MailNameKind,
    id: &uuid::Uuid,
) -> AppResult<u64> {
    use kutup_crypto::account_record::{self, AccountRecordPurpose};
    let bytes = account_record::decode_record_b64(sealed_b64, AccountRecordPurpose::MailName)
        .map_err(|_| AppError::bad_request("name is not a sealed mail name"))?;
    let revision = kutup_crypto::mail_names::validate_name(&bytes, binding, kind, id.as_bytes())
        .map_err(|_| AppError::bad_request("name is not this place's sealed name"))?;
    stored(revision)?;
    Ok(revision)
}

/// The account's key binding, which its records bind.
pub async fn key_binding<'e, E>(executor: E, user_id: uuid::Uuid) -> AppResult<String>
where
    E: sqlx::PgExecutor<'e>,
{
    let binding: Option<String> = sqlx::query_scalar("SELECT key_binding FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(executor)
        .await?;
    binding.ok_or_else(|| AppError::bad_request("the account has no key binding"))
}

/// A rename of a mail folder, label or filter: `new` must follow `base` (the
/// revision of the name the rename started from), which must be the stored
/// name's. The caller then writes only where the stored name is still
/// `stored` (a compare-and-swap) and answers [`conflict`] if it is not.
pub fn check_rename(stored: &str, new: u64, base: Option<i64>) -> AppResult<()> {
    let base =
        base.ok_or_else(|| AppError::bad_request("a rename names the revision it started from"))?;
    let current = stored_or_conflict(mail_name(stored)?)?;
    if current != base {
        return Err(conflict("this name was changed elsewhere", current));
    }
    check_follows(new, base).map(drop)
}

/// What to answer when a guarded rename wrote nothing: the row's name now
/// (`None`: the row is gone).
pub fn rename_lost(now: Option<String>, gone: &'static str) -> AppError {
    match now.map(|name| mail_name(&name).and_then(stored_or_conflict)) {
        None => AppError::not_found(gone),
        Some(Ok(current)) => conflict("this name was changed elsewhere", current),
        Some(Err(error)) => error,
    }
}

fn stored_or_conflict(revision: u64) -> AppResult<i64> {
    i64::try_from(revision).map_err(|_| AppError::internal("a stored revision is too large"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_revision_must_be_above_its_base() {
        assert_eq!(check_follows(5, 4).unwrap(), 5);
        assert_eq!(
            check_follows(1_791_633_600_000, 0).unwrap(),
            1_791_633_600_000
        );
        assert!(check_follows(4, 4).is_err());
        assert!(check_follows(3, 4).is_err());
        assert!(check_follows(5, -1).is_err());
        assert!(check_follows(u64::MAX, 0).is_err());
        assert!(check_follows(MAX_REVISION + 1, 0).is_err());
        assert_eq!(check_follows(MAX_REVISION, 0).unwrap(), MAX_REVISION as i64);
    }
}
