//! Block, spam and allow lists (docs/plans/mail-filters.md, F3), as
//! Proton's: an address or a whole domain. Checked where every copy is
//! stored ([`super::insert_message`]), before filters:
//!
//! - *block*: the message is accepted (refusing would tell the sender) and
//!   not stored ("won't be delivered and will be permanently deleted");
//! - *spam*: it is filed in Spam;
//! - *allow*: it is kept out of Spam, only when its From is authenticated
//!   (DMARC passed, or a Kutup account sent it), so a forged From cannot
//!   use someone's allow entry.
//!
//! An address entry wins over one for its domain.

use sqlx::{Postgres, Transaction};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Spam,
    Block,
    Allow,
}

impl Kind {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "spam" => Some(Self::Spam),
            "block" => Some(Self::Block),
            "allow" => Some(Self::Allow),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Spam => "spam",
            Self::Block => "block",
            Self::Allow => "allow",
        }
    }
}

/// Lowercase as addresses compare: Turkish İ as i (a plain `to_lowercase`
/// makes it "i̇"); ı stays ı, a letter of its own in domain names.
fn lower(text: &str) -> String {
    text.trim().replace('İ', "i").to_lowercase()
}

/// A list entry as typed: a lowercase address, or a domain (an `@example.com`
/// is the domain). None when it is neither.
pub fn normalise(pattern: &str) -> Option<String> {
    let pattern = lower(pattern);
    let pattern = pattern.strip_prefix('@').unwrap_or(&pattern).to_string();
    let domain_ok = |d: &str| {
        d.len() >= 3
            && d.contains('.')
            && !d.starts_with(['.', '-'])
            && !d.ends_with(['.', '-'])
            && d.chars()
                .all(|c| c.is_alphanumeric() || c == '.' || c == '-')
    };
    let ok = match pattern.split_once('@') {
        Some((local, domain)) => {
            !local.is_empty()
                && local.len() <= 64
                && !local
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control() || c == '@')
                && domain_ok(domain)
        }
        None => domain_ok(&pattern),
    };
    (ok && pattern.len() <= 320).then_some(pattern)
}

/// [`normalise`], then kept as senders are compared ([`super::sender_key`]):
/// an address of this server folded.
pub fn normalise_for(server_name: &str, pattern: &str) -> Option<String> {
    normalise(pattern).map(|pattern| super::sender_key(server_name, &pattern))
}

/// The entry that applies to mail from `from` in `user_id`'s lists. A sender
/// of this server is matched in any spelling of their name: entries keep
/// its addresses folded (`mail_addresses.folded`).
pub async fn verdict(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    from: &str,
) -> sqlx::Result<Option<Kind>> {
    let from = lower(from);
    let Some((_, domain)) = from.rsplit_once('@') else {
        return Ok(None);
    };
    let kind: Option<String> = sqlx::query_scalar(
        "SELECT kind FROM mail_sender_rules
          WHERE user_id = $1
            AND pattern IN ($2, $3, (SELECT folded FROM mail_addresses
                                       WHERE folded = kutup_address_folded($2)
                                       LIMIT 1))
          ORDER BY (pattern = $3) ASC LIMIT 1",
    )
    .bind(user_id)
    .bind(&from)
    .bind(domain)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(kind.as_deref().and_then(Kind::parse))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_are_addresses_or_domains() {
        assert_eq!(
            normalise(" News@Shop.Example ").as_deref(),
            Some("news@shop.example")
        );
        assert_eq!(normalise("@shop.example").as_deref(), Some("shop.example"));
        assert_eq!(normalise("ŞİRKET.com.tr").as_deref(), Some("şirket.com.tr"));
        for bad in [
            "",
            "shop",
            "a@",
            "@",
            "a b@x.com",
            "x@-bad.com",
            ".example.com",
            "a@@x.com",
        ] {
            assert_eq!(normalise(bad), None, "{bad:?}");
        }
        assert_eq!(Kind::parse("block"), Some(Kind::Block));
        assert_eq!(Kind::Allow.as_str(), "allow");
    }
}
