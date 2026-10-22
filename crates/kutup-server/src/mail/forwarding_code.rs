//! Verifying a forwarding's destination (docs/plans/mail-forwarding.md,
//! "Verification"): a 6-digit code mailed to the destination, which the
//! forwarder enters. Nothing is forwarded before.
//!
//! The code is kept as an HMAC under a key derived from `MAIL_FORWARDING_KEYS`
//! (the key's version beside it), never in the clear: a row read from the
//! database doesn't give the code away by trying the million values. It
//! lasts `forwarding_code_minutes`, takes `forwarding_code_attempts` wrong
//! guesses before it is void, and a forwarding sends at most
//! `forwarding_code_resends` a minute and `forwarding_invites` a day, inside
//! the account's `forwarding_confirmations_sent` a day.

use hmac::{Hmac, Mac as _};
use rand::RngCore as _;
use time::OffsetDateTime;
use uuid::Uuid;

use super::forwarding::{self, Charge};
use crate::opaque_setup::OpaqueSetupKeys;
use crate::ratelimit::{Limit, RateLimiter};
use crate::AppState;

type HmacSha256 = Hmac<sha2::Sha256>;

/// The label the code key is derived under, apart from every other use of
/// `MAIL_FORWARDING_KEYS`.
const CODE_KEY_LABEL: &[u8] = b"kutup mail forwarding code v1";

/// Codes a forwarding may send in a minute (`forwarding_code_resends`).
static RESENDS: std::sync::LazyLock<RateLimiter> =
    std::sync::LazyLock::new(|| RateLimiter::registered(Limit::ForwardingCodeResends));

/// The code key of `MAIL_FORWARDING_KEYS` version `version`.
fn code_key(keys: &OpaqueSetupKeys, version: u16) -> Option<[u8; 32]> {
    let key = keys.get(version)?;
    let mut mac = HmacSha256::new_from_slice(key).expect("any key length");
    mac.update(CODE_KEY_LABEL);
    Some(mac.finalize().into_bytes().into())
}

fn code_mac(key: &[u8; 32], forwarding: Uuid, code: &str) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(key).expect("any key length");
    mac.update(forwarding.as_bytes());
    mac.update(code.as_bytes());
    mac
}

/// A new code: six decimal digits, uniform (draws past the last whole
/// million of `u32` are drawn again).
fn new_code() -> String {
    const LIMIT: u32 = u32::MAX - u32::MAX % 1_000_000;
    loop {
        let draw = rand::rngs::OsRng.next_u32();
        if draw < LIMIT {
            return format!("{:06}", draw % 1_000_000);
        }
    }
}

/// Whether `code` looks like one: six ASCII digits.
pub fn well_formed(code: &str) -> bool {
    code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit())
}

/// Whether `code` is the one kept for `forwarding`, in constant time.
/// False when its key version is gone from the configuration.
pub fn matches(
    keys: &OpaqueSetupKeys,
    version: u16,
    forwarding: Uuid,
    code: &str,
    kept: &[u8],
) -> bool {
    code_key(keys, version)
        .is_some_and(|key| code_mac(&key, forwarding, code).verify_slice(kept).is_ok())
}

/// The label an outside forwarding's stop link is derived under.
const STOP_LABEL: &[u8] = b"kutup mail forwarding stop v1";

/// An outside forwarding's stop link token and the hash it is found by
/// (`confirmation_hash`): derived from the current forwarding key, so every
/// code mail carries the same link, which keeps working until the key is
/// rotated. The link can only refuse a forwarding, never start one.
pub fn stop_token(keys: &OpaqueSetupKeys, forwarding: Uuid) -> Option<(String, Vec<u8>)> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use sha2::Digest as _;
    let (_, key) = keys.current()?;
    let mut mac = HmacSha256::new_from_slice(key).expect("any key length");
    mac.update(STOP_LABEL);
    mac.update(forwarding.as_bytes());
    let token: [u8; 32] = mac.finalize().into_bytes().into();
    Some((
        URL_SAFE_NO_PAD.encode(token),
        sha2::Sha256::digest(token).to_vec(),
    ))
}

/// Why no code was issued.
#[derive(Debug)]
pub enum NotIssued {
    /// No `MAIL_FORWARDING_KEYS`: forwarding is unavailable.
    Unavailable,
    /// Too soon after the last, or the forwarding's or account's day is spent.
    RateLimited,
    Database(sqlx::Error),
}

impl From<sqlx::Error> for NotIssued {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

/// A code issued in a transaction, to mail once it has committed.
pub struct Issued {
    pub forwarding: Uuid,
    code: String,
    minutes: i64,
}

/// Issues `forwarding` a new code (the last one void), charging the
/// forwarding's and its account's allowances. The forwarding is locked by
/// the caller.
pub async fn issue(
    keys: &OpaqueSetupKeys,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    forwarding: Uuid,
) -> Result<Issued, NotIssued> {
    let (version, _) = keys.current().ok_or(NotIssued::Unavailable)?;
    let key = code_key(keys, version).expect("the current key is configured");
    let account: Uuid = sqlx::query_scalar("SELECT user_id FROM mail_forwardings WHERE id = $1")
        .bind(forwarding)
        .fetch_one(&mut **tx)
        .await?;
    // Both allowances or neither: a refused code charges nothing.
    let mut savepoint = sqlx::Acquire::begin(&mut **tx).await?;
    if !forwarding::charge(&mut savepoint, account, Charge::Confirmation).await? {
        return Err(NotIssued::RateLimited);
    }
    let minutes = i64::from(forwarding::limit(Limit::ForwardingCodeMinutes, None)).max(1);
    let code = new_code();
    let kept = code_mac(&key, forwarding, &code)
        .finalize()
        .into_bytes()
        .to_vec();
    let issued = sqlx::query(
        "UPDATE mail_forwardings SET
                invites_today = CASE WHEN day = current_date THEN invites_today + 1 ELSE 1 END,
                sent_today = CASE WHEN day = current_date THEN sent_today ELSE 0 END,
                bounces_today = CASE WHEN day = current_date THEN bounces_today ELSE 0 END,
                day = current_date,
                code_hash = $2, code_key_version = $3,
                code_expires_at = now() + ($4 * interval '1 minute'),
                code_attempts = 0, code_sent_at = now(), updated_at = now()
          WHERE id = $1 AND (day <> current_date OR invites_today < $5)",
    )
    .bind(forwarding)
    .bind(&kept)
    .bind(i16::try_from(version).unwrap_or(i16::MAX))
    .bind(minutes)
    .bind(forwarding::limit(Limit::ForwardingInvites, None))
    .execute(&mut *savepoint)
    .await?;
    if issued.rows_affected() != 1 {
        return Err(NotIssued::RateLimited);
    }
    // Last, so a refusal above spends none of the minute's sends.
    if !RESENDS.allow(&forwarding.to_string()) {
        return Err(NotIssued::RateLimited);
    }
    savepoint.commit().await?;
    Ok(Issued {
        forwarding,
        code,
        minutes,
    })
}

/// The verification mail's subject and body, in the forwarder's language.
fn text(
    language: &str,
    forwarder: &str,
    forwardee: &str,
    code: &str,
    minutes: i64,
) -> (String, String) {
    if language == "tr" {
        (
            format!("{forwarder} adresinden yönlendirme için doğrulama kodu"),
            format!(
                "{forwarder}, postalarını bu adrese ({forwardee}) yönlendirmek istiyor.\r\n\r\n\
Doğrulama kodu: {code}\r\n\r\n\
Kod {minutes} dakika geçerlidir. Yönlendirmeyi kuran kişi kodu Kutup Posta'nın yönlendirme ayarlarına girer.\r\n\r\n\
Bunu beklemiyorsanız bu e-postayı yok sayın: kod girilmeden hiçbir şey yönlendirilmez.\r\n"
            ),
        )
    } else {
        (
            format!("Verification code for forwarding from {forwarder}"),
            format!(
                "{forwarder} wants to forward mail to this address ({forwardee}).\r\n\r\n\
Verification code: {code}\r\n\r\n\
The code expires in {minutes} minutes. Whoever set up the forwarding enters it in Kutup Mail's forwarding settings.\r\n\r\n\
If you didn't expect this, ignore this email: nothing is forwarded until the code is entered.\r\n"
            ),
        )
    }
}

/// The line that lets an outside destination refuse the forwarding (it
/// can only stop one, never start it).
fn stop_line(language: &str, link: &str) -> String {
    if language == "tr" {
        format!("\r\nBu yönlendirmeyi şimdi ya da daha sonra reddetmek için: {link}\r\n")
    } else {
        format!("\r\nTo refuse this forwarding, now or later: {link}\r\n")
    }
}

/// Mails an issued code to the forwarding's destination: into a Kutup
/// address's inbox, or outside through submission with a link that only
/// stops it (`stop_token`). Failures are logged: the forwarder can send
/// another code.
pub async fn send(state: &AppState, issued: Issued, stop_token: Option<&str>) {
    if let Err(error) = try_send(state, &issued, stop_token).await {
        tracing::warn!(forwarding = %issued.forwarding, error = %error, "mail: a forwarding code was not sent");
    }
}

async fn try_send(
    state: &AppState,
    issued: &Issued,
    stop_token: Option<&str>,
) -> anyhow::Result<()> {
    let (kind, forwarder, forwardee, language): (String, String, String, Option<String>) =
        sqlx::query_as(
            "SELECT f.kind, a.address, f.forwardee_email, p.language
               FROM mail_forwardings f
               JOIN mail_addresses a ON a.id = f.forwarder_address_id
               LEFT JOIN user_ui_preferences p ON p.user_id = f.user_id
              WHERE f.id = $1",
        )
        .bind(issued.forwarding)
        .fetch_one(&state.pool)
        .await?;
    let language = language.unwrap_or_else(|| "en".into());
    let (subject, mut body) = text(
        &language,
        &forwarder,
        &forwardee,
        &issued.code,
        issued.minutes,
    );
    if kind != "outside" {
        return super::notice::deliver_to(state, &forwardee, &subject, &body).await;
    }
    // Under Mail's own rules: none goes out for an account that may not
    // send outside now.
    let account: Uuid = sqlx::query_scalar("SELECT user_id FROM mail_forwardings WHERE id = $1")
        .bind(issued.forwarding)
        .fetch_one(&state.pool)
        .await?;
    if let Some(code) = forwarding::outside_refusal(state, account)
        .await
        .map_err(|error| anyhow::anyhow!("{error:?}"))?
    {
        anyhow::bail!("not sent: {code}");
    }
    if let Some(token) = stop_token {
        body.push_str(&stop_line(
            &language,
            &format!("{}/email-forwarding#{token}", state.config.apps.account),
        ));
    }
    let server = &state.config.chat_server_name;
    let from = forwarding::return_path(
        &state.config.mail_forwarding_keys,
        server,
        issued.forwarding,
    )
    .ok_or_else(|| anyhow::anyhow!("no MAIL_FORWARDING_KEYS"))?;
    let date = OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc2822)?;
    let subject = super::auto_reply::header_text(&subject);
    let message = format!(
        "From: {server} <postmaster@{server}>\r\nTo: <{forwardee}>\r\nSubject: {subject}\r\n\
Date: {date}\r\nMessage-ID: <{}@{server}>\r\nAuto-Submitted: auto-generated\r\n\
MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\
Content-Transfer-Encoding: 8bit\r\n\r\n{body}",
        Uuid::new_v4().simple(),
    );
    super::submit::submit(
        &state.config.mail_submission_addr,
        &format!("kutup@{server}"),
        &state.config.mail_inbound_token,
        super::submit::Envelope {
            from: &from,
            recipients: &[forwardee],
            message: message.as_bytes(),
        },
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> OpaqueSetupKeys {
        OpaqueSetupKeys::parse("1:ERERERERERERERERERERERERERERERERERERERERERE=,2:IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=").unwrap()
    }

    #[test]
    fn codes_are_six_digits() {
        for _ in 0..1000 {
            let code = new_code();
            assert!(well_formed(&code), "{code}");
        }
        assert!(!well_formed("12345"));
        assert!(!well_formed("1234567"));
        assert!(!well_formed("12345a"));
        assert!(!well_formed("١٢٣٤٥٦"));
    }

    #[test]
    fn a_code_matches_only_its_forwarding_and_key() {
        let keys = keys();
        let forwarding = Uuid::new_v4();
        let kept = code_mac(&code_key(&keys, 2).unwrap(), forwarding, "042137")
            .finalize()
            .into_bytes()
            .to_vec();
        assert!(matches(&keys, 2, forwarding, "042137", &kept));
        assert!(!matches(&keys, 2, forwarding, "042138", &kept));
        assert!(!matches(&keys, 2, Uuid::new_v4(), "042137", &kept));
        assert!(!matches(&keys, 1, forwarding, "042137", &kept));
        assert!(!matches(&keys, 3, forwarding, "042137", &kept));
        // The code key is the forwarding key's, under its own label.
        assert_ne!(code_key(&keys, 2).unwrap(), *keys.get(2).unwrap());
    }

    #[test]
    fn the_mail_says_who_asks_and_has_no_verifying_link() {
        for language in ["en", "tr"] {
            let (subject, body) = text(language, "ada@kutup.test", "bob@example.com", "042137", 15);
            assert!(subject.contains("ada@kutup.test"));
            assert!(body.contains("042137") && body.contains("15"));
            assert!(body.contains("bob@example.com"));
            assert!(!body.contains("http"));
        }
    }
}
