//! Who other people are (docs/plans/drive-identity-pins.md), as Drive on the
//! web and Chat see it: a key the server hands out is trusted only as far as
//! the person's account authority signed it (the Drive key binding) and that
//! authority is the one this account pinned for the address. The pins are the
//! account's synced list, shared with every app; the CLI reads and writes the
//! same one. A doubt warns and asks, as the apps do; it does not refuse.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::account_ref::AccountRef;
use kutup_crypto::drive_key_binding;
use kutup_crypto::identity::{incarnation_id_from_authority_public, AccountIdentityKeysV1};
use kutup_crypto::identity_pins::{self, IdentityPinsV1, PinState, PinUpdate, Recorded};
use kutup_crypto::safety_number;

use crate::api::types::IdentityPinsWrite;
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
    /// The address they were looked up by.
    pub account: String,
    /// Who they are, for good: their server and account id.
    pub account_ref: AccountRef,
    pub authority: String,
    pub hpke: String,
    pub signing: String,
    pub binding: Option<String>,
}

/// This account's address and keys.
pub struct Me {
    pub account: String,
    /// This account, for good: the server and its id (`users.id`).
    pub account_ref: AccountRef,
    /// The account's key binding, which its own seals (the pin list) bind.
    binding: String,
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
            account_ref: AccountRef::new(&server, &ctx.session.user_id)
                .context("this session's account id is not valid")?,
            binding: ctx.session.binding().to_string(),
            identity: AccountIdentityKeysV1::derive(&master_key)?,
            master_key,
            profile: profile.to_string(),
        })
    }

    fn authority(&self) -> [u8; 32] {
        self.identity.authority_public_key()
    }

    /// The account head for this profile (docs/plans/rollback-protection.md).
    pub fn head<'a>(&self, ctx: &'a Ctx) -> Result<crate::account_head::CliHead<'a>> {
        crate::account_head::CliHead::open(
            &ctx.client,
            &self.master_key,
            &self.binding,
            &self.identity.incarnation_id(),
            config::data_dir(&self.profile)?,
        )
    }

    /// This profile's sealed revision guard.
    pub fn guard(&self) -> Result<crate::account_head::Guard> {
        crate::account_head::CliHead::guard(&config::data_dir(&self.profile)?, &self.master_key)
    }
}

/// Looks `account` up: here, or through their server.
pub fn published(ctx: &Ctx, me: &Me, account: &str) -> Result<Published> {
    let (username, server) = account
        .split_once('@')
        .ok_or_else(|| anyhow!("{account} is not an account address (user@server)"))?;
    let local = me.account.split_once('@').map(|(_, s)| s) == Some(server);
    let person = if local {
        let user = ctx.client.get_user_by_address(account)?;
        Published {
            // On this server the account id is the user id.
            account_ref: AccountRef::new(server, &user.user_id)
                .with_context(|| format!("the lookup for {account} gave no valid account id"))?,
            account: user.account,
            authority: user.account_authority_public_key,
            hpke: user.drive_hpke_public_key,
            signing: user.drive_signing_public_key,
            binding: user.drive_key_binding,
        }
    } else {
        let user = ctx.client.get_fed_pubkey(username, server)?;
        Published {
            account_ref: AccountRef::new(server, &user.account_id)
                .with_context(|| format!("{server} gave no valid account id for {account}"))?,
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
    drive_key_binding::verify(&person.account_ref, &authority, &hpke, &signing, &binding).is_ok()
}

// ------------------------------------------------------------------ pins

/// What the revision guard calls the pin list (as the web does).
pub const PINS_GUARD_SCOPE: &str = "identity-pins";
pub const PINS_GUARD_ID: &str = "list";
/// The pin list is one value of the account head's `pins` scope.
const HEAD_SCOPE: &str = "pins";
const HEAD_ID: &str = "pins";

/// Reads the list and opens it, held to `index` and to this device's guard.
fn read_pins(
    ctx: &Ctx,
    me: &Me,
    index: &crate::account_head::Index,
) -> Result<(u64, IdentityPinsV1)> {
    let key = identity_pins::derive_key(&me.master_key)?;
    let guard = me.guard()?;
    let (revision, list) = match ctx.client.get_identity_pins()? {
        None => {
            if guard.seen(PINS_GUARD_SCOPE, PINS_GUARD_ID)? > 0 {
                bail!("the server returned no identity pin list, though this device has seen one");
            }
            index.expect_listing([])?;
            (0, IdentityPinsV1::default())
        }
        Some(record) => {
            let sealed = STANDARD
                .decode(&record.envelope)
                .context("identity pins are not base64")?;
            let (list, revision) = identity_pins::open(&key, &me.binding, &sealed)?;
            index.expect(HEAD_ID, revision)?;
            (revision, list)
        }
    };
    if revision > 0 {
        guard
            .accept(PINS_GUARD_SCOPE, PINS_GUARD_ID, revision)
            .context("the server returned an older identity pin list than this device has seen")?;
    }
    Ok((revision, list))
}

/// The account's pin list and its revision, held to the account head (read
/// again once when a write landed between the two reads).
pub fn load_pins(ctx: &Ctx, me: &Me) -> Result<(u64, IdentityPinsV1)> {
    let mut head = me.head(ctx)?;
    let index = |head: &mut crate::account_head::CliHead<'_>| match head.index(HEAD_SCOPE) {
        Ok(index) => Ok(index),
        // Blocked on another history: reads go on, held to this device's own
        // guard; listed writes stop (exit 6).
        Err(error) if error.downcast_ref::<crate::errors::HeadBlocked>().is_some() => {
            eprintln!("note: {error}");
            Ok(crate::account_head::Index::uncovered(HEAD_SCOPE))
        }
        Err(error) => Err(error),
    };
    let first = index(&mut head)?;
    match read_pins(ctx, me, &first) {
        Ok(read) => Ok(read),
        Err(_) => {
            let again = index(&mut head)?;
            read_pins(ctx, me, &again)
        }
    }
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Records `update` about `account` at `authority` (the rules every app shares:
/// `identity_pins::record`) with the next account head; merges with whatever
/// another app stored meanwhile.
fn pin(ctx: &Ctx, me: &Me, account: &str, authority: &str, update: PinUpdate) -> Result<Recorded> {
    let key = identity_pins::derive_key(&me.master_key)?;
    let guard = me.guard()?;
    let guard = &guard;
    let mut head = me.head(ctx)?;
    let mut outcome = None;
    head.listed_write(HEAD_SCOPE, |index, _attempt| {
        let (revision, mut list) = read_pins(ctx, me, index)?;
        let before = list.clone();
        let since = identity_pins::since_from_unix(now_seconds());
        let recorded = identity_pins::record(&mut list, account, authority, update, &since)?;
        outcome = Some(recorded.clone());
        if list == before {
            return Ok(None);
        }
        // A time, above every revision seen (docs/plans/drive-identity-pins.md).
        let next = guard
            .next(PINS_GUARD_SCOPE, PINS_GUARD_ID, revision)?
            .max(now_millis());
        let sealed = identity_pins::seal(&key, &me.binding, next, &list)?;
        let envelope = STANDARD.encode(sealed);
        Ok(Some(crate::account_head::Edit {
            changes: vec![(HEAD_ID.to_owned(), Some(next))],
            send: Box::new(move |sealed_head: &str| {
                let stored = ctx.client.put_identity_pins(&IdentityPinsWrite {
                    base_revision: revision,
                    envelope,
                    head: Some(sealed_head.to_owned()),
                })?;
                if !stored {
                    return Ok(None);
                }
                guard.accept(PINS_GUARD_SCOPE, PINS_GUARD_ID, next)?;
                Ok(Some(()))
            }),
        }))
    })?;
    outcome.context("the identity pin list was not read")
}

// ---------------------------------------------------------------- checks

/// How far `account`'s `claimed` keys can be trusted; pins its authority the
/// first time it is met with a valid binding.
pub fn check(ctx: &Ctx, me: &Me, account: &str, claimed: &Claimed) -> Result<Status> {
    if account == me.account {
        return Ok(Status::Ok { verified: true });
    }
    let person = published(ctx, me, account)?;
    // This account under another of its names (an old address): by its id.
    if person.account_ref == me.account_ref {
        return Ok(Status::Ok { verified: true });
    }
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
        None => match pin(ctx, me, account, &person.authority, PinUpdate::FirstSeen)? {
            // Someone the user knew had this address and is elsewhere now: this
            // is another person (accept with `kutup identity trust`).
            Recorded::FormerAddressTaken { .. } => Ok(Status::Changed),
            // An identity the user replaced, turning up again: its trust is
            // revoked (accept it with `kutup identity trust`, or verify it).
            Recorded::ReplacedIdentity { .. } => Ok(Status::Changed),
            // The same account, pinned under another of its names.
            Recorded::KnownElsewhere { pin } => Ok(Status::Ok {
                verified: pin.state == PinState::Verified,
            }),
            Recorded::Pinned | Recorded::Unchanged => Ok(Status::Ok { verified: false }),
        },
    }
}

/// The safety number to compare with `account`, for their current identity.
pub fn safety(
    ctx: &Ctx,
    me: &Me,
    account: &str,
) -> Result<(safety_number::SafetyNumberV2, Published)> {
    let person = published(ctx, me, account)?;
    if !bound(&person) {
        bail!("{account} has not signed their Drive keys yet: nothing to compare");
    }
    let authority =
        key32(&person.authority).ok_or_else(|| anyhow!("{account}'s authority key is invalid"))?;
    Ok((safety_number::derive(&me.authority(), &authority)?, person))
}

/// Mark `account` verified (the user compared the safety number with them);
/// a changed identity is accepted with it.
pub fn verify(ctx: &Ctx, me: &Me, account: &str, person: &Published) -> Result<()> {
    pin(ctx, me, account, &person.authority, PinUpdate::Verified).map(drop)
}

/// Trust `account`'s current identity from now on, without comparing it.
pub fn trust(ctx: &Ctx, me: &Me, account: &str) -> Result<()> {
    let person = published(ctx, me, account)?;
    if !bound(&person) {
        bail!("{account} has not signed their Drive keys yet");
    }
    // A new identity is trusted as seen, never as verified.
    match pin(ctx, me, account, &person.authority, PinUpdate::Accepted)? {
        // The same person under another address: renamed. Following their
        // rename moves the pin; trusting it here would pin them twice.
        Recorded::KnownElsewhere { pin } => bail!(
            "the identity at {account} is someone you already know as {}: their address changed, and it is followed once their rename is confirmed",
            pin.account
        ),
        _ => Ok(()),
    }
}
