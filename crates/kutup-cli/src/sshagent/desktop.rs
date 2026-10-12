//! Asking on the desktop, for an agent without a terminal (the one `kutup
//! ssh-agent install` starts at login). The same question as on the
//! terminal, in a dialog that gives up after a minute:
//!
//! - `KUTUP_SSH_ASKPASS` or `SSH_ASKPASS`: an OpenSSH askpass program, run
//!   as `ssh-agent` runs it for a confirm-constrained key
//!   (`SSH_ASKPASS_PROMPT=confirm`; success allows once).
//! - Linux: `zenity`, else `kdialog`, with "Allow once", "Allow for this
//!   host" (when the host is known) and "Deny".
//! - macOS: a dialog through `osascript`, with the same three buttons.
//!
//! The question's text is passed as an argument, never through a shell or
//! into a script, and stripped of markup and control characters. No dialog
//! program, no answer, or an error: denied.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use super::approval::{summary, Approver, Decision, SignRequest};

/// How long a dialog waits before it counts as "Deny".
pub const ANSWER_WITHIN: Duration = Duration::from_secs(60);
const TITLE: &str = "Kutup SSH agent";
pub const ALLOW_ONCE: &str = "Allow once";
pub const ALLOW_HOST: &str = "Allow for this host";
pub const DENY: &str = "Deny";

/// A program that can ask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asker {
    Askpass(PathBuf),
    Zenity(PathBuf),
    Kdialog(PathBuf),
    Osascript(PathBuf),
}

impl Asker {
    /// The first of: the askpass program in the environment, then the
    /// platform's dialog program.
    pub fn find() -> Option<Self> {
        Self::find_in(
            |name| std::env::var_os(name),
            std::env::var_os("PATH").unwrap_or_default(),
        )
    }

    pub fn find_in(env: impl Fn(&str) -> Option<OsString>, path: OsString) -> Option<Self> {
        for name in ["KUTUP_SSH_ASKPASS", "SSH_ASKPASS"] {
            if let Some(program) = env(name).filter(|value| !value.is_empty()) {
                return Some(Self::Askpass(PathBuf::from(program)));
            }
        }
        let on_path = |name: &str| {
            std::env::split_paths(&path)
                .map(|dir| dir.join(name))
                .find(|candidate| is_executable(candidate))
        };
        if cfg!(target_os = "macos") {
            return Some(Self::Osascript(
                on_path("osascript").unwrap_or_else(|| PathBuf::from("/usr/bin/osascript")),
            ));
        }
        on_path("zenity")
            .map(Self::Zenity)
            .or_else(|| on_path("kdialog").map(Self::Kdialog))
    }

    /// The command that asks `text`, with or without the host choice.
    pub fn command(&self, text: &str, host_known: bool) -> Command {
        let seconds = ANSWER_WITHIN.as_secs().to_string();
        match self {
            Self::Askpass(program) => {
                let mut command = Command::new(program);
                command
                    .arg(format!("{text}\n\nAllow once?"))
                    .env("SSH_ASKPASS_PROMPT", "confirm");
                command
            }
            Self::Zenity(program) => {
                let mut command = Command::new(program);
                command.args([
                    "--question",
                    "--no-markup",
                    "--title",
                    TITLE,
                    "--icon=dialog-password",
                    "--text",
                    text,
                    "--ok-label",
                    ALLOW_ONCE,
                    "--cancel-label",
                    DENY,
                    "--timeout",
                    &seconds,
                ]);
                if host_known {
                    command.args(["--extra-button", ALLOW_HOST]);
                }
                command
            }
            Self::Kdialog(program) => {
                let mut command = Command::new(program);
                command.args(["--title", TITLE]);
                if host_known {
                    command.args([
                        "--yesnocancel",
                        text,
                        "--yes-label",
                        ALLOW_ONCE,
                        "--no-label",
                        ALLOW_HOST,
                        "--cancel-label",
                        DENY,
                    ]);
                } else {
                    command.args([
                        "--yesno",
                        text,
                        "--yes-label",
                        ALLOW_ONCE,
                        "--no-label",
                        DENY,
                    ]);
                }
                command
            }
            Self::Osascript(program) => {
                let buttons = if host_known {
                    format!("{{\"{DENY}\", \"{ALLOW_HOST}\", \"{ALLOW_ONCE}\"}}")
                } else {
                    format!("{{\"{DENY}\", \"{ALLOW_ONCE}\"}}")
                };
                // The text arrives as an argument (`argv`), never inside the
                // script.
                let script = format!(
                    "on run argv\n\
                     set answer to display dialog (item 1 of argv) with title \"{TITLE}\" \
                     buttons {buttons} default button \"{ALLOW_ONCE}\" cancel button \"{DENY}\" \
                     with icon caution giving up after {seconds}\n\
                     if gave up of answer then return \"{DENY}\"\n\
                     return button returned of answer\n\
                     end run"
                );
                let mut command = Command::new(program);
                command.args(["-e", &script, text]);
                command
            }
        }
    }

    /// Reads the answer from the program's exit status and output.
    pub fn decision(
        &self,
        success: bool,
        code: Option<i32>,
        stdout: &str,
        host_known: bool,
    ) -> Decision {
        let said = stdout.trim();
        let host = |decision: Decision| {
            if decision == Decision::Host && !host_known {
                Decision::Deny
            } else {
                decision
            }
        };
        match self {
            Self::Askpass(_) => {
                if success {
                    Decision::Once
                } else {
                    Decision::Deny
                }
            }
            // OK: once; the extra button prints its label and exits 1;
            // "Deny", closing it and the timeout (5) print nothing.
            Self::Zenity(_) => match (success, said) {
                (true, _) => Decision::Once,
                (false, ALLOW_HOST) if code == Some(1) => host(Decision::Host),
                _ => Decision::Deny,
            },
            // Yes 0, No 1, Cancel 2.
            Self::Kdialog(_) => match (code, host_known) {
                (Some(0), _) => Decision::Once,
                (Some(1), true) => Decision::Host,
                _ => Decision::Deny,
            },
            Self::Osascript(_) => match (success, said) {
                (true, ALLOW_ONCE) => Decision::Once,
                (true, ALLOW_HOST) => host(Decision::Host),
                _ => Decision::Deny,
            },
        }
    }
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

/// The question as plain text: no markup a dialog could render (kdialog
/// takes text that looks like HTML as HTML) and no control characters.
pub fn plain(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '<' => '‹',
            '>' => '›',
            '&' => '+',
            '\n' => '\n',
            c if c.is_control() => ' ',
            c => c,
        })
        .collect()
}

/// Asks in a desktop dialog, one question at a time.
pub struct DesktopApprover {
    asker: Option<Asker>,
    asking: Mutex<()>,
}

impl DesktopApprover {
    pub fn new(asker: Option<Asker>) -> Self {
        Self {
            asker,
            asking: Mutex::new(()),
        }
    }
}

impl Approver for DesktopApprover {
    fn ask(&self, request: &SignRequest) -> Decision {
        let _one_at_a_time = self.asking.lock().unwrap_or_else(|e| e.into_inner());
        let Some(asker) = &self.asker else {
            eprintln!("kutup ssh-agent: no dialog program to ask with (zenity, kdialog or SSH_ASKPASS); denied");
            return Decision::Deny;
        };
        let host_known = request.connection.host.is_some();
        let text = plain(&summary(request).join("\n"));
        let child = asker
            .command(&text, host_known)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();
        let mut child = match child {
            Ok(child) => child,
            Err(error) => {
                eprintln!("kutup ssh-agent: could not ask ({error}); denied");
                return Decision::Deny;
            }
        };
        // A program that does not give up by itself is stopped a little
        // after the minute.
        let deadline = std::time::Instant::now() + ANSWER_WITHIN + Duration::from_secs(5);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
            }
        };
        let Some(status) = status else {
            return Decision::Deny;
        };
        let mut stdout = String::new();
        if let Some(out) = child.stdout.take() {
            use std::io::Read;
            let _ = out.take(4096).read_to_string(&mut stdout);
        }
        asker.decision(status.success(), status.code(), &stdout, host_known)
    }
}

/// Answers on the terminal when there is one, else on the desktop.
pub struct AutoApprover {
    terminal: super::approval::TerminalApprover,
    desktop: DesktopApprover,
}

impl AutoApprover {
    pub fn new() -> Self {
        Self {
            terminal: super::approval::TerminalApprover::new(),
            desktop: DesktopApprover::new(Asker::find()),
        }
    }
}

impl Approver for AutoApprover {
    fn ask(&self, request: &SignRequest) -> Decision {
        if std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .is_ok()
        {
            self.terminal.ask(request)
        } else {
            self.desktop.ask(request)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::sshagent::proto::Purpose;
    use crate::sshagent::Connection;

    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn ask(asker: Asker, host: bool) -> Decision {
        let purpose = Purpose::Login {
            user: "ayşe".into(),
        };
        let connection = Connection {
            host: host.then(|| "SHA256:host".into()),
            host_names: vec!["git.example.org".into()],
            forwarded: false,
            process: Some("ssh <b>x</b>".into()),
        };
        DesktopApprover::new(Some(asker)).ask(&SignRequest {
            key_title: "Sunucu".into(),
            key_fingerprint: "SHA256:key".into(),
            vault: "Keys.kdbx".into(),
            purpose: &purpose,
            connection: &connection,
        })
    }

    #[test]
    fn the_askpass_in_the_environment_comes_first_then_zenity_then_kdialog() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let path = std::env::join_paths([&bin]).unwrap();
        let none = |_: &str| None;
        if cfg!(target_os = "linux") {
            assert_eq!(Asker::find_in(none, path.clone()), None);
            script(&bin, "kdialog", "exit 0");
            assert_eq!(
                Asker::find_in(none, path.clone()),
                Some(Asker::Kdialog(bin.join("kdialog")))
            );
            script(&bin, "zenity", "exit 0");
            assert_eq!(
                Asker::find_in(none, path.clone()),
                Some(Asker::Zenity(bin.join("zenity")))
            );
            // Not executable: not a candidate.
            std::fs::write(bin.join("zenity"), "x").unwrap();
            std::fs::set_permissions(bin.join("zenity"), std::fs::Permissions::from_mode(0o644))
                .unwrap();
            assert_eq!(
                Asker::find_in(none, path.clone()),
                Some(Asker::Kdialog(bin.join("kdialog")))
            );
        }
        let env = |name: &str| {
            (name == "SSH_ASKPASS").then(|| OsString::from("/usr/lib/ssh/ssh-askpass"))
        };
        assert_eq!(
            Asker::find_in(env, path.clone()),
            Some(Asker::Askpass("/usr/lib/ssh/ssh-askpass".into()))
        );
        let both = |name: &str| Some(OsString::from(format!("/bin/{name}")));
        assert_eq!(
            Asker::find_in(both, path),
            Some(Asker::Askpass("/bin/KUTUP_SSH_ASKPASS".into()))
        );
    }

    #[test]
    fn dialogs_get_the_text_as_an_argument_and_the_right_buttons() {
        let words = |asker: Asker, host: bool| -> Vec<String> {
            asker
                .command("a \"b\" $(c)", host)
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect()
        };
        let zenity = words(Asker::Zenity("/z".into()), true);
        assert!(zenity.contains(&"--no-markup".into()));
        assert!(zenity.windows(2).any(|w| w == ["--text", "a \"b\" $(c)"]));
        assert!(zenity
            .windows(2)
            .any(|w| w == ["--extra-button", ALLOW_HOST]));
        assert!(zenity.windows(2).any(|w| w == ["--timeout", "60"]));
        assert!(!words(Asker::Zenity("/z".into()), false).contains(&ALLOW_HOST.into()));
        let kdialog = words(Asker::Kdialog("/k".into()), true);
        assert!(kdialog
            .windows(2)
            .any(|w| w == ["--yesnocancel", "a \"b\" $(c)"]));
        assert!(words(Asker::Kdialog("/k".into()), false).contains(&"--yesno".into()));
        let osascript = words(Asker::Osascript("/o".into()), true);
        assert_eq!(osascript.last().unwrap(), "a \"b\" $(c)");
        assert!(
            !osascript[1].contains("$(c)"),
            "the text never enters the script"
        );
        assert!(osascript[1].contains(ALLOW_HOST));
        assert!(osascript[1].contains("giving up after 60"));
        let askpass = Asker::Askpass("/a".into()).command("x", true);
        assert!(askpass
            .get_envs()
            .any(|(k, v)| k == "SSH_ASKPASS_PROMPT" && v == Some(std::ffi::OsStr::new("confirm"))));
    }

    #[test]
    fn answers_are_read_from_exit_codes_and_output() {
        let z = Asker::Zenity("/z".into());
        assert_eq!(z.decision(true, Some(0), "", true), Decision::Once);
        assert_eq!(
            z.decision(false, Some(1), "Allow for this host\n", true),
            Decision::Host
        );
        assert_eq!(
            z.decision(false, Some(1), "Allow for this host\n", false),
            Decision::Deny
        );
        assert_eq!(z.decision(false, Some(1), "", true), Decision::Deny);
        assert_eq!(z.decision(false, Some(5), "", true), Decision::Deny);
        let k = Asker::Kdialog("/k".into());
        assert_eq!(k.decision(true, Some(0), "", true), Decision::Once);
        assert_eq!(k.decision(false, Some(1), "", true), Decision::Host);
        assert_eq!(k.decision(false, Some(1), "", false), Decision::Deny);
        assert_eq!(k.decision(false, Some(2), "", true), Decision::Deny);
        let o = Asker::Osascript("/o".into());
        assert_eq!(
            o.decision(true, Some(0), "Allow once\n", true),
            Decision::Once
        );
        assert_eq!(
            o.decision(true, Some(0), "Allow for this host", true),
            Decision::Host
        );
        assert_eq!(o.decision(true, Some(0), "Deny", true), Decision::Deny);
        assert_eq!(o.decision(false, Some(1), "", true), Decision::Deny);
        let a = Asker::Askpass("/a".into());
        assert_eq!(a.decision(true, Some(0), "", true), Decision::Once);
        assert_eq!(a.decision(false, Some(1), "", true), Decision::Deny);
    }

    #[test]
    fn the_text_carries_no_markup_or_control_characters() {
        assert_eq!(
            plain("ssh <b>x</b> & y\u{7}\u{1b}[31m\nnext"),
            "ssh ‹b›x‹/b› + y  [31m\nnext"
        );
    }

    #[test]
    fn a_dialog_program_is_run_and_its_answer_taken() {
        let dir = tempfile::tempdir().unwrap();
        let seen = dir.path().join("seen");
        let allow = script(
            dir.path(),
            "askpass-yes",
            &format!(
                "printf '%s|%s' \"$SSH_ASKPASS_PROMPT\" \"$1\" > '{}'; exit 0",
                seen.display()
            ),
        );
        assert_eq!(ask(Asker::Askpass(allow), true), Decision::Once);
        let said = std::fs::read_to_string(&seen).unwrap();
        assert!(said.starts_with("confirm|"), "{said}");
        assert!(said.contains("wants to use the key \"Sunucu\""), "{said}");
        assert!(said.contains("ssh ‹b›x‹/b›"), "{said}");
        assert!(said.contains("login as ayşe to git.example.org"), "{said}");
        let deny = script(dir.path(), "askpass-no", "exit 1");
        assert_eq!(ask(Asker::Askpass(deny), true), Decision::Deny);
        let host = script(dir.path(), "zenity", "echo 'Allow for this host'; exit 1");
        assert_eq!(ask(Asker::Zenity(host.clone()), true), Decision::Host);
        assert_eq!(ask(Asker::Zenity(host), false), Decision::Deny);
        assert_eq!(
            ask(Asker::Askpass(dir.path().join("missing")), true),
            Decision::Deny
        );
        assert_eq!(
            DesktopApprover::new(None).ask(&SignRequest {
                key_title: "k".into(),
                key_fingerprint: "f".into(),
                vault: "v".into(),
                purpose: &Purpose::Unknown,
                connection: &Connection::default(),
            }),
            Decision::Deny
        );
    }
}
