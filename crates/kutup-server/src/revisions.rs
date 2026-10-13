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

/// A header revision as the database stores it.
pub fn stored(revision: u64) -> AppResult<i64> {
    i64::try_from(revision).map_err(|_| AppError::bad_request("the revision is too large"))
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

/// The revision of a sealed mail folder, label or filter name (base64), as
/// its header carries it; refuses anything else.
pub fn mail_name(sealed_b64: &str) -> AppResult<u64> {
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sealed_b64)
        .map_err(|_| AppError::bad_request("name is not base64"))?;
    kutup_crypto::mail_names::inspect_name(&bytes)
        .map_err(|_| AppError::bad_request("name is not a sealed mail name"))
}

/// A rename of a mail folder, label or filter: `new` must follow `base` (the
/// revision of the name the rename started from), which must be the stored
/// name's. The caller then writes only where the stored name is still
/// `stored` (a compare-and-swap) and answers [`conflict`] if it is not.
pub fn check_rename(stored: &str, new: &str, base: Option<i64>) -> AppResult<()> {
    let base =
        base.ok_or_else(|| AppError::bad_request("a rename names the revision it started from"))?;
    let current = stored_or_conflict(mail_name(stored)?)?;
    if current != base {
        return Err(conflict("this name was changed elsewhere", current));
    }
    check_follows(mail_name(new)?, base).map(drop)
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
    }
}
