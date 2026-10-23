//! Notices from the server to an account, as mail in its own inbox: stored
//! as inbound mail is, encrypted to the account's address key, from
//! `postmaster@` the server.

use uuid::Uuid;

use crate::AppState;

/// Why an account lost a custom domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainLost {
    /// Another account proved it controls the domain.
    Transferred,
    /// Its DNS stopped proving it past the grace.
    Lapsed,
    /// An administrator deactivated it.
    Deactivated,
}

/// Tells `user` it lost the custom domain `name`, in its inbox. A failure
/// is logged, never raised: the security event already records the loss.
pub async fn domain_lost(state: &AppState, user: Uuid, name: &str, why: DomainLost) {
    let reason = match why {
        DomainLost::Transferred => format!(
            "Another account proved that it controls {name}: its DNS now carries that \
             account's verification record and no longer yours. The domain moved to it."
        ),
        DomainLost::Lapsed => format!(
            "{name}'s DNS records stopped pointing to this server for longer than the \
             grace period. If you still own it, restore its records and add it again."
        ),
        DomainLost::Deactivated => format!(
            "An administrator of this server deactivated {name}. Contact them if you \
             think this is a mistake."
        ),
    };
    let body = format!(
        "{reason}\r\n\r\nYour addresses on {name} no longer receive or send mail. \
         The mail they received stays in your mailbox.\r\n"
    );
    if let Err(error) = deliver(state, user, &format!("You no longer hold {name}"), &body).await {
        tracing::warn!(error = %error, "mail: the domain-lost notice was not delivered");
    }
}

async fn deliver(state: &AppState, user: Uuid, subject: &str, body: &str) -> anyhow::Result<()> {
    // The account's own address on the server's domain, the oldest first.
    let address: Option<String> = sqlx::query_scalar(
        "SELECT address FROM mail_addresses
          WHERE user_id = $1 AND domain_id IS NULL AND state = 'active'
          ORDER BY created_at LIMIT 1",
    )
    .bind(user)
    .fetch_optional(&state.pool)
    .await?;
    let Some(address) = address else {
        return Ok(());
    };
    deliver_to(state, &address, subject, body).await
}

/// Delivers a notice to the Kutup address `address` (on this server), as
/// mail from `postmaster@` into its owner's inbox.
pub async fn deliver_to(
    state: &AppState,
    address: &str,
    subject: &str,
    body: &str,
) -> anyhow::Result<()> {
    let recipient = super::resolve(state, address)
        .await
        .map_err(|reply| anyhow::anyhow!("{} {}", reply.code, reply.text))?;
    let server = &state.config.chat_server_name;
    let date =
        time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc2822)?;
    let raw = format!(
        "From: {server} <postmaster@{server}>\r\nTo: <{address}>\r\nSubject: {}\r\n\
         Date: {date}\r\nMessage-ID: <{}@{server}>\r\nMIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\
         Auto-Submitted: auto-generated\r\n\r\n{body}",
        super::auto_reply::header_text(subject),
        Uuid::new_v4().simple()
    );
    let reply = super::store(state, &recipient, raw.as_bytes()).await;
    if reply.code >= 400 {
        anyhow::bail!("{} {}", reply.code, reply.text);
    }
    Ok(())
}
