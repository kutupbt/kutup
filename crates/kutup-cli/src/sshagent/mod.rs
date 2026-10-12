//! The `kutup` SSH agent (docs/plans/pass.md, K3b; research 19, "SSH agent
//! in the `kutup` CLI"). Opt-in: it runs only when started. It serves the
//! SSH keys kept in KeePass vault entries (KeeAgent form, as KeePassXC and
//! Strongbox keep them) from the vaults `kutup sync` keeps in a folder, so it
//! works offline. Public keys are listed as soon as the vault opens; a
//! private key is decrypted only for a signature that was approved, kept in
//! memory only, and wiped after a while unused.

pub mod approval;
pub mod hosts;
pub mod peer;
pub mod proto;
pub mod server;

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use kutup_pass::ssh::{sign, verify_session_bind, SshKeyEntry};
use ssh_key::PrivateKey;

use approval::{Approver, Decision, SignRequest};
use proto::{Purpose, Request};

/// One key the agent serves, and the vault it came from.
pub struct LoadedKey {
    pub vault: String,
    pub entry: SshKeyEntry,
}

/// What a connection told the agent about itself (`session-bind`).
#[derive(Debug, Default, Clone)]
pub struct Connection {
    /// The destination's host key fingerprint, once bound.
    pub host: Option<String>,
    /// The destination's names from `known_hosts`.
    pub host_names: Vec<String>,
    /// The request comes through `ssh -A` from another machine.
    pub forwarded: bool,
    /// The requesting process, when the system says (`ssh`, `git`…).
    pub process: Option<String>,
}

/// How the agent decides.
pub struct Policy {
    /// Never ask (for keys used from scripts); forwarded requests still ask.
    pub no_confirm: bool,
    /// Decrypted keys and remembered approvals are forgotten after this long
    /// unused.
    pub idle: Duration,
}

pub struct State {
    pub keys: Vec<LoadedKey>,
    decrypted: HashMap<String, PrivateKey>,
    /// (key fingerprint, host fingerprint) approved "for this host" until lock.
    remembered: HashSet<(String, String)>,
    last_use: Instant,
}

impl State {
    pub fn new(keys: Vec<LoadedKey>) -> Self {
        Self {
            keys,
            decrypted: HashMap::new(),
            remembered: HashSet::new(),
            last_use: Instant::now(),
        }
    }

    /// Forgets decrypted keys and approvals (idle, or asked to).
    pub fn lock(&mut self) {
        self.decrypted.clear();
        self.remembered.clear();
    }

    /// Locks if unused for `idle`; true when it did.
    pub fn lock_if_idle(&mut self, idle: Duration) -> bool {
        let holding = !self.decrypted.is_empty() || !self.remembered.is_empty();
        if holding && self.last_use.elapsed() >= idle {
            self.lock();
            return true;
        }
        false
    }
}

fn failure() -> Vec<u8> {
    vec![proto::FAILURE]
}

/// Answers one request. `state` is locked only around what needs it, never
/// while asking the person.
pub fn handle(
    request: Request,
    connection: &mut Connection,
    state: &std::sync::Mutex<State>,
    policy: &Policy,
    approver: &dyn Approver,
    log: &dyn Fn(String),
) -> Vec<u8> {
    match request {
        Request::Identities => {
            let state = state.lock().unwrap_or_else(|e| e.into_inner());
            let mut out = vec![proto::IDENTITIES_ANSWER];
            proto::put_u32(&mut out, state.keys.len() as u32);
            for key in &state.keys {
                proto::put_string(&mut out, &key.entry.public_blob());
                proto::put_string(&mut out, key.entry.comment().as_bytes());
            }
            out
        }
        Request::SessionBind {
            host_key,
            session_id,
            signature,
            forwarding,
        } => {
            let Some(host) = verify_session_bind(&host_key, &session_id, &signature) else {
                log("refused a session-bind whose host signature does not verify".into());
                return failure();
            };
            // Once a connection has been forwarded, it stays flagged.
            connection.forwarded |= forwarding;
            connection.host_names = hosts::names_for(&host_key);
            connection.host = Some(host);
            vec![proto::SUCCESS]
        }
        Request::Sign { key, data, flags } => {
            let (entry, vault) = {
                let state = state.lock().unwrap_or_else(|e| e.into_inner());
                match state.keys.iter().find(|k| k.entry.public_blob() == key) {
                    Some(found) => (found.entry.clone(), found.vault.clone()),
                    None => return failure(),
                }
            };
            let fingerprint = entry.fingerprint();
            let remembered = connection.host.as_ref().is_some_and(|host| {
                let state = state.lock().unwrap_or_else(|e| e.into_inner());
                state
                    .remembered
                    .contains(&(fingerprint.clone(), host.clone()))
            });
            let purpose = proto::purpose(&data);
            let request = SignRequest {
                key_title: entry.title.clone(),
                key_fingerprint: fingerprint.clone(),
                vault,
                purpose: &purpose,
                connection,
            };
            let allowed = if remembered || (policy.no_confirm && !connection.forwarded) {
                true
            } else {
                match approver.ask(&request) {
                    Decision::Once => true,
                    Decision::Host => {
                        if let Some(host) = &connection.host {
                            let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
                            state.remembered.insert((fingerprint.clone(), host.clone()));
                        }
                        true
                    }
                    Decision::Deny => false,
                }
            };
            if !allowed {
                log(format!("denied {} ({})", entry.title, describe(&purpose)));
                return failure();
            }
            let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
            state.last_use = Instant::now();
            if !state.decrypted.contains_key(&fingerprint) {
                match entry.private_key() {
                    Ok(private) => {
                        state.decrypted.insert(fingerprint.clone(), private);
                    }
                    Err(error) => {
                        log(format!("{}: {error}", entry.title));
                        return failure();
                    }
                }
            }
            let private = &state.decrypted[&fingerprint];
            match sign(private, &data, flags) {
                Ok(signature) => {
                    log(format!(
                        "signed with {} ({})",
                        entry.title,
                        describe(&purpose)
                    ));
                    let mut out = vec![proto::SIGN_RESPONSE];
                    proto::put_string(&mut out, &signature);
                    out
                }
                Err(error) => {
                    log(format!("{}: {error}", entry.title));
                    failure()
                }
            }
        }
        Request::Other(_) => failure(),
    }
}

pub fn describe(purpose: &Purpose) -> String {
    match purpose {
        Purpose::Login { user } => format!("login as {user}"),
        Purpose::Signature { namespace } if namespace == "git" => "git signature".into(),
        Purpose::Signature { namespace } => format!("{namespace} signature"),
        Purpose::Unknown => "signature".into(),
    }
}

#[cfg(test)]
mod tests;
