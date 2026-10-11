//! Who other people are (docs/plans/drive-identity-pins.md), as Drive on the
//! web and Chat see it: a key the server hands out is trusted only as far as
//! the person's account authority signed it (the Drive key binding) and that
//! authority is the one this account pinned for the address. The pins are the
//! account's synced list, shared with every app; the CLI reads and writes the
//! same one. A doubt warns and asks, as the apps do; it does not refuse.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::drive_key_binding;
use kutup_crypto::identity::{incarnation_id_from_authority_public, AccountIdentityKeysV1};
use kutup_crypto::identity_pins::{self, IdentityPinV1, IdentityPinsV1, PinState};
use kutup_crypto::safety_number;

use crate::api::types::IdentityPinsRecord;
use crate::config;
use crate::context::Ctx;

/// What can be said about a person's keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Signed by their authority, the one pinned (or met now and pinned).
    Ok { verified: bool },
    /// Their account has not signed its keys yet.
    Unproven,
    /// The keys are not the ones their authority signed.
    Invalid,
    /// Another authority than the one this account met before.
    Changed,
}

impl Status {
    pub fn in_doubt(self) -> bool {
        matches!(self, Status::Invalid | Status::Changed)
    }

    /// One word for tables and JSON.
    pub fn label(self) -> &'static str {
        match self {
            Status::Ok { verified: true } => "verified",
            Status::Ok { verified: false } => "trusted",
            Status::Unproven => "unproven",
            Status::Invalid => "invalid",
            Status::Changed => "changed",
        }
    }

    /// A sentence for a warning.
    pub fn warning(self, account: &str) -> String {
        match self {
            Status::Changed => format!(
                "{account} is not the account you met before: an administrator may have reset it, or the server may be passing off someone else's keys. Compare safety numbers ('kutup identity verify {account}') or trust the new identity ('kutup identity trust {account}')."
            ),
            Status::Invalid => format!(
                "the keys the server gave for {account} are not signed by their account; the server may be able to read what is shared with them, or this may not come from them."
            ),
            _ => String::new(),
        }
    }
}

/// The keys a share or lookup put to someone; what is absent is not compared.
#[derive(Default)]
pub struct Claimed<'a> {
    pub hpke: Option<&'a str>,
    pub signing: Option<&'a str>,
    pub incarnation: Option<&'a str>,
}

/// A person as their server describes them.
pub struct Published {
    pub account: String,
    pub authority: String,
    pub hpke: String,
    pub signing: String,
    pub binding: Option<String>,
}

/// This account's address and keys.
pub struct Me {
    pub account: String,
    pub identity: AccountIdentityKeysV1,
    master_key: [u8; 32],
    profile: String,
}

impl Me {
    pub fn of(ctx: &Ctx, profile: &str) -> Result<Me> {
        let master_key: [u8; 32] = ctx
            .session
            .master_key_bytes()?
            .as_slice()
            .try_into()
            .context("master key must be 32 bytes")?;
        let server = ctx.client.settings()?.chat.server_name;
        Ok(Me {
            account: format!("{}@{server}", ctx.session.username),
            identity: AccountIdentityKeysV1::derive(&master_key)?,
            master_key,
            profile: profile.to_string(),
        })
    }

    fn authority(&self) -> [u8; 32] {
        self.identity.authority_public_key()
    }
}

/// Looks `account` up: here, or through their server.
pub fn published(ctx: &Ctx, me: &Me, account: &str) -> Result<Published> {
    let (username, server) = account
        .split_once('@')
        .ok_or_else(|| anyhow!("{account} is not an account address (user@server)"))?;
    let local = me.account.split_once('@').map(|(_, s)| s) == Some(server);
    let person = if local {
        let user = ctx.client.get_user_by_email(account)?;
        Published {
            account: user.account,
            authority: user.account_authority_public_key,
            hpke: user.drive_hpke_public_key,
            signing: user.drive_signing_public_key,
            binding: user.drive_key_binding,
        }
    } else {
        let user = ctx.client.get_fed_pubkey(username, server)?;
        Published {
            account: user.account,
            authority: user.account_authority_public_key,
            hpke: user.drive_hpke_public_key,
            signing: user.drive_signing_public_key,
            binding: user.drive_key_binding,
        }
    };
    if person.account != account {
        bail!("the lookup for {account} answered for {}", person.account);
    }
    Ok(person)
}

fn key32(value: &str) -> Option<[u8; 32]> {
    let bytes = STANDARD.decode(value).ok()?;
    (STANDARD.encode(&bytes) == value).then_some(())?;
    bytes.try_into().ok()
}

fn bound(person: &Published) -> bool {
    let (Some(authority), Some(hpke), Some(signing), Some(binding)) = (
        key32(&person.authority),
        key32(&person.hpke),
        key32(&person.signing),
        person
            .binding
            .as_deref()
            .and_then(|b| STANDARD.decode(b).ok()),
    ) else {
        return false;
    };
    drive_key_binding::verify(&person.account, &authority, &hpke, &signing, &binding).is_ok()
}

// ------------------------------------------------------------------ pins

fn revision_file(me: &Me) -> Result<std::path::PathBuf> {
    Ok(config::data_dir(&me.profile)?.join("identity-pins-revision"))
}

/// The highest revision this device has seen: a server cannot quietly hand
/// back an older list.
fn highest_seen(me: &Me) -> u64 {
    revision_file(me)
        .ok()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0)
}

fn remember(me: &Me, revision: u64) {
    if revision > highest_seen(me) {
        if let Ok(path) = revision_file(me) {
            let _ = std::fs::write(path, revision.to_string());
        }
    }
}

/// The account's pin list and its revision.
pub fn load_pins(ctx: &Ctx, me: &Me) -> Result<(u64, IdentityPinsV1)> {
    let key = identity_pins::derive_key(&me.master_key)?;
    let (revision, list) = match ctx.client.get_identity_pins()? {
        None => (0, IdentityPinsV1::default()),
        Some(record) => {
            let sealed = STANDARD
                .decode(&record.envelope)
                .context("identity pins are not base64")?;
            (
                record.revision,
                identity_pins::open(&key, &me.account, record.revision, &sealed)?,
            )
        }
    };
    if revision < highest_seen(me) {
        bail!("the server returned an older identity pin list than this device has seen");
    }
    remember(me, revision);
    Ok((revision, list))
}

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Pins `account` to `authority` in `state`, keeping the replaced identity in
/// its history; merges with whatever another app stored meanwhile.
fn pin(ctx: &Ctx, me: &Me, account: &str, authority: &str, state: PinState) -> Result<()> {
    let key = identity_pins::derive_key(&me.master_key)?;
    for _ in 0..5 {
        let (revision, mut list) = load_pins(ctx, me)?;
        let index = list.pins.iter().position(|p| p.account == account);
        let mut replaced = Vec::new();
        if let Some(i) = index {
            let previous = &list.pins[i];
            if previous.authority_public_key == authority
                && (previous.state == state || previous.state == PinState::Verified)
            {
                return Ok(());
            }
            let previous = list.pins.remove(i);
            replaced = previous.replaced.clone();
            if previous.authority_public_key != authority {
                replaced.push(incarnation_id_from_authority_public(&previous.authority()?));
            }
        }
        let excess = replaced.len().saturating_sub(identity_pins::MAX_REPLACED);
        replaced.drain(..excess);
        list.pins.push(IdentityPinV1 {
            account: account.to_string(),
            authority_public_key: authority.to_string(),
            state,
            since: identity_pins::since_from_unix(now_seconds()),
            replaced,
        });
        list.pins.sort_by(|a, b| a.account.cmp(&b.account));
        let next = revision + 1;
        let sealed = identity_pins::seal(&key, &me.account, next, &list)?;
        if ctx.client.put_identity_pins(&IdentityPinsRecord {
            revision: next,
            envelope: STANDARD.encode(sealed),
        })? {
            remember(me, next);
            return Ok(());
        }
    }
    bail!("the identity pin list kept changing")
}

// ---------------------------------------------------------------- checks

/// How far `account`'s `claimed` keys can be trusted; pins its authority the
/// first time it is met with a valid binding.
pub fn check(ctx: &Ctx, me: &Me, account: &str, claimed: &Claimed) -> Result<Status> {
    if account == me.account {
        return Ok(Status::Ok { verified: true });
    }
    let person = published(ctx, me, account)?;
    if claimed.hpke.is_some_and(|k| k != person.hpke)
        || claimed.signing.is_some_and(|k| k != person.signing)
    {
        return Ok(Status::Invalid);
    }
    let Some(authority) = key32(&person.authority) else {
        return Ok(Status::Invalid);
    };
    if claimed
        .incarnation
        .is_some_and(|i| i != incarnation_id_from_authority_public(&authority))
    {
        return Ok(Status::Invalid);
    }
    let (_, list) = load_pins(ctx, me)?;
    let pinned = list.pins.iter().find(|p| p.account == account);
    if person.binding.is_none() {
        // A binding is never withdrawn: a pinned account without one is a server leaving it out.
        return Ok(if pinned.is_some() {
            Status::Invalid
        } else {
            Status::Unproven
        });
    }
    if !bound(&person) {
        return Ok(Status::Invalid);
    }
    match pinned {
        Some(p) if p.authority_public_key == person.authority => Ok(Status::Ok {
            verified: p.state == PinState::Verified,
        }),
        Some(_) => Ok(Status::Changed),
        None => {
            pin(ctx, me, account, &person.authority, PinState::Seen)?;
            Ok(Status::Ok { verified: false })
        }
    }
}

/// The safety number to compare with `account`, for their current identity.
pub fn safety(
    ctx: &Ctx,
    me: &Me,
    account: &str,
) -> Result<(safety_number::SafetyNumberV1, Published)> {
    let person = published(ctx, me, account)?;
    if !bound(&person) {
        bail!("{account} has not signed their Drive keys yet: nothing to compare");
    }
    let authority =
        key32(&person.authority).ok_or_else(|| anyhow!("{account}'s authority key is invalid"))?;
    Ok((
        safety_number::derive(&me.account, &me.authority(), account, &authority)?,
        person,
    ))
}

/// Mark `account` verified (the user compared the safety number with them);
/// a changed identity is accepted with it.
pub fn verify(ctx: &Ctx, me: &Me, account: &str, person: &Published) -> Result<()> {
    pin(ctx, me, account, &person.authority, PinState::Verified)
}

/// Trust `account`'s current identity from now on, without comparing it.
pub fn trust(ctx: &Ctx, me: &Me, account: &str) -> Result<()> {
    let person = published(ctx, me, account)?;
    if !bound(&person) {
        bail!("{account} has not signed their Drive keys yet");
    }
    let (_, list) = load_pins(ctx, me)?;
    let replacing = list.pins.iter().find(|p| p.account == account);
    if replacing.is_some_and(|p| p.authority_public_key == person.authority) {
        return Ok(());
    }
    // A new identity is trusted as seen, never as verified.
    pin(ctx, me, account, &person.authority, PinState::Seen)
}

/// Signs this account's Drive key binding when it has none yet (an account
/// made before bindings; the web app does the same at sign-in).
pub fn ensure_binding(ctx: &Ctx, me: &Me) -> Result<()> {
    if ctx.client.has_drive_key_binding()? {
        return Ok(());
    }
    let binding = drive_key_binding::sign(&me.identity, &me.account)?;
    ctx.client.put_drive_key_binding(&STANDARD.encode(binding))
}
