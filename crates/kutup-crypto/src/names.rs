//! Folded names (docs/plans/username-renames.md, "Folded names"): one account
//! per name in all its spellings, as Proton and Gmail have it. A name's folded
//! form is its local part, lowercase, without `.`, `_` and `-`. Availability
//! (registration, renames, mail groups), sign-in, the OPAQUE fake answer and
//! lockout, and mail delivery to this server's own domains all compare folded
//! forms; the stored username keeps the spelling its owner chose.
//!
//! Only ASCII is folded (usernames are ASCII; another character in a mail
//! local part is kept as it is and never matches a username).

/// The folded form of a name or a mail local part.
pub fn fold(name: &str) -> String {
    name.chars()
        .filter(|c| !matches!(c, '.' | '_' | '-'))
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// The folded form of `local@domain`: the local part folded, the domain
/// lowercase. `None` for a string with no `@` or an empty side.
pub fn fold_address(address: &str) -> Option<String> {
    let (local, domain) = address.rsplit_once('@')?;
    let local = fold(local);
    if local.is_empty() || domain.is_empty() {
        return None;
    }
    Some(format!("{local}@{}", domain.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn punctuation_and_case_fold_away() {
        for (name, folded) in [
            ("ada", "ada"),
            ("Ada.L", "adal"),
            ("ada_l", "adal"),
            ("a..b", "ab"),
            ("_a", "a"),
            ("a-", "a"),
            ("a_-b", "ab"),
            ("A.d-A_l", "adal"),
            ("name.123", "name123"),
            ("ça", "ça"),
        ] {
            assert_eq!(fold(name), folded, "{name}");
        }
        assert_eq!(fold_address("Ada.L@Kutup.Dev").as_deref(), Some("adal@kutup.dev"));
        assert_eq!(fold_address("_.-@kutup.dev"), None);
        assert_eq!(fold_address("ada"), None);
    }
}
