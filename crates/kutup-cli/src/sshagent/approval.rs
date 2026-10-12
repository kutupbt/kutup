//! Asking before a key is used (Bitwarden's model): which process, which
//! key, to log in where (from `session-bind`) or what it signs, and whether
//! the request is forwarded from another machine (`ssh -A`), which is flagged
//! loudly. Allow once, allow for this host until the agent locks, or deny.

use std::io::{BufRead, BufReader, Write};
use std::sync::Mutex;

use super::proto::Purpose;
use super::{describe, Connection};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Once,
    /// Allowed for this key and host until the agent locks.
    Host,
    Deny,
}

pub struct SignRequest<'a> {
    pub key_title: String,
    pub key_fingerprint: String,
    pub vault: String,
    pub purpose: &'a Purpose,
    pub connection: &'a Connection,
}

pub trait Approver: Send + Sync {
    fn ask(&self, request: &SignRequest) -> Decision;
}

/// What the person is asked.
pub fn prompt_text(request: &SignRequest) -> String {
    let c = request.connection;
    let mut lines = Vec::new();
    lines.push(String::new());
    if c.forwarded {
        lines.push(
            "  !! FORWARDED: this request comes from another machine through `ssh -A`.".into(),
        );
    }
    lines.push(format!(
        "  {} wants to use the key \"{}\" ({}) from {}",
        c.process.as_deref().unwrap_or("A program"),
        request.key_title,
        request.key_fingerprint,
        request.vault
    ));
    let what = describe(request.purpose);
    match (&c.host, c.host_names.first()) {
        (Some(_), Some(name)) => lines.push(format!("  for a {what} to {name}")),
        (Some(host), None) => lines.push(format!("  for a {what} to the host with key {host}")),
        (None, _) => lines.push(format!("  for a {what}")),
    }
    let choices = if c.host.is_some() {
        "  Allow? [o]nce, [h]ost until the agent locks, [N]o: "
    } else {
        "  Allow? [o]nce, [N]o: "
    };
    lines.push(choices.into());
    lines.join("\n")
}

/// Reads the answer.
pub fn decide(answer: &str, host_known: bool) -> Decision {
    match answer.trim().to_lowercase().as_str() {
        "o" | "once" | "y" | "yes" => Decision::Once,
        "h" | "host" if host_known => Decision::Host,
        _ => Decision::Deny,
    }
}

/// Asks on the terminal the agent runs in (`/dev/tty`), one question at a
/// time. Without a terminal every request is denied.
pub struct TerminalApprover {
    asking: Mutex<()>,
}

impl TerminalApprover {
    pub fn new() -> Self {
        Self {
            asking: Mutex::new(()),
        }
    }
}

impl Approver for TerminalApprover {
    fn ask(&self, request: &SignRequest) -> Decision {
        let _one_at_a_time = self.asking.lock().unwrap_or_else(|e| e.into_inner());
        let Ok(tty) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
        else {
            eprintln!("kutup ssh-agent: no terminal to ask on; denied (start it with --no-confirm for unattended use)");
            return Decision::Deny;
        };
        let mut out = match tty.try_clone() {
            Ok(out) => out,
            Err(_) => return Decision::Deny,
        };
        if write!(out, "{}", prompt_text(request))
            .and_then(|_| out.flush())
            .is_err()
        {
            return Decision::Deny;
        }
        let mut answer = String::new();
        if BufReader::new(tty).read_line(&mut answer).is_err() {
            return Decision::Deny;
        }
        decide(&answer, request.connection.host.is_some())
    }
}
