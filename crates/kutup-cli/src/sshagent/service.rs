//! `kutup ssh-agent install` (docs/plans/pass.md, "SSH agent"): the agent
//! started at login by the user's own service manager, a systemd user unit
//! on Linux and a launchd agent on macOS, with nothing installed system-wide
//! and no secret in the unit. It asks on the desktop (`--approve desktop`)
//! and opens vaults with the keys kept in the account (`kutup login` and
//! `kutup pass keep`), since a service has neither a terminal nor a prompt.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// The systemd unit's name, and launchd's label.
pub const UNIT: &str = "kutup-ssh-agent.service";
pub const LABEL: &str = "dev.kutup.ssh-agent";

/// What the service runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub program: PathBuf,
    pub profile: String,
    pub local_dir: PathBuf,
    pub collection_id: String,
    pub socket: PathBuf,
    pub idle: u64,
    pub no_confirm: bool,
    /// Settings from the installing shell a service would not otherwise see
    /// (the askpass program; never a secret).
    pub environment: Vec<(String, String)>,
}

impl Service {
    /// The agent's command line.
    pub fn arguments(&self) -> Vec<String> {
        let mut args = vec![
            self.program.to_string_lossy().into_owned(),
            "--profile".into(),
            self.profile.clone(),
            "ssh-agent".into(),
            self.local_dir.to_string_lossy().into_owned(),
            self.collection_id.clone(),
            "--socket".into(),
            self.socket.to_string_lossy().into_owned(),
            "--idle".into(),
            self.idle.to_string(),
            "--approve".into(),
            "desktop".into(),
        ];
        if self.no_confirm {
            args.push("--no-confirm".into());
        }
        args
    }

    /// A systemd user unit.
    pub fn systemd_unit(&self) -> String {
        let command: Vec<String> = self.arguments().iter().map(|a| systemd_quote(a)).collect();
        let environment: String = self
            .environment
            .iter()
            .map(|(name, value)| {
                // Environment= expands specifiers but not `$`.
                format!(
                    "Environment={}\n",
                    systemd_quote(&format!("{name}={value}")).replace("$$", "$")
                )
            })
            .collect();
        format!(
            "# Written by `kutup ssh-agent install`; removed by `kutup ssh-agent uninstall`.\n\
             [Unit]\n\
             Description=Kutup SSH agent (SSH keys from your Kutup Pass vaults)\n\
             Documentation=https://kutup.dev\n\
             \n\
             [Service]\n\
             Type=simple\n\
             {environment}\
             ExecStart={}\n\
             Restart=on-failure\n\
             RestartSec=5\n\
             \n\
             [Install]\n\
             WantedBy=default.target\n",
            command.join(" ")
        )
    }

    /// A launchd agent.
    pub fn launchd_plist(&self, log: &Path) -> String {
        let arguments: String = self
            .arguments()
            .iter()
            .map(|a| format!("    <string>{}</string>\n", xml_escape(a)))
            .collect();
        let log = xml_escape(&log.to_string_lossy());
        let environment = if self.environment.is_empty() {
            String::new()
        } else {
            let pairs: String = self
                .environment
                .iter()
                .map(|(name, value)| {
                    format!(
                        "    <key>{}</key>\n    <string>{}</string>\n",
                        xml_escape(name),
                        xml_escape(value)
                    )
                })
                .collect();
            format!("  <key>EnvironmentVariables</key>\n  <dict>\n{pairs}  </dict>\n")
        };
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <!-- Written by `kutup ssh-agent install`; removed by `kutup ssh-agent uninstall`. -->\n\
             <plist version=\"1.0\">\n\
             <dict>\n\
             \x20 <key>Label</key>\n\
             \x20 <string>{LABEL}</string>\n\
             \x20 <key>ProgramArguments</key>\n\
             \x20 <array>\n\
             {arguments}\
             \x20 </array>\n\
             {environment}\
             \x20 <key>RunAtLoad</key>\n\
             \x20 <true/>\n\
             \x20 <key>KeepAlive</key>\n\
             \x20 <dict>\n\
             \x20   <key>SuccessfulExit</key>\n\
             \x20   <false/>\n\
             \x20 </dict>\n\
             \x20 <key>ProcessType</key>\n\
             \x20 <string>Interactive</string>\n\
             \x20 <key>StandardOutPath</key>\n\
             \x20 <string>{log}</string>\n\
             \x20 <key>StandardErrorPath</key>\n\
             \x20 <string>{log}</string>\n\
             </dict>\n\
             </plist>\n"
        )
    }
}

/// One `ExecStart=` word: double-quoted, with systemd's escapes (`\`, `"`),
/// its specifiers (`%`) and its environment expansion (`$`) taken literally.
pub fn systemd_quote(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '%' => out.push_str("%%"),
            '$' => out.push_str("$$"),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Where the service manager reads the service from.
pub fn service_file() -> Result<PathBuf> {
    if cfg!(target_os = "macos") {
        let home = dirs::home_dir().context("no home folder")?;
        Ok(home
            .join("Library/LaunchAgents")
            .join(format!("{LABEL}.plist")))
    } else if cfg!(target_os = "linux") {
        let config = std::env::var_os("XDG_CONFIG_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| dirs::home_dir().map(|home| home.join(".config")))
            .context("no home folder")?;
        Ok(config.join("systemd/user").join(UNIT))
    } else {
        bail!("kutup ssh-agent install supports Linux (systemd) and macOS (launchd)")
    }
}

/// macOS: where the agent writes what it says.
pub fn launchd_log() -> Result<PathBuf> {
    let home = dirs::home_dir().context("no home folder")?;
    Ok(home.join("Library/Logs/kutup-ssh-agent.log"))
}

/// The service file's text for this platform.
pub fn service_text(service: &Service) -> Result<String> {
    if cfg!(target_os = "macos") {
        Ok(service.launchd_plist(&launchd_log()?))
    } else {
        Ok(service.systemd_unit())
    }
}

/// Runs a service manager command; its error output in the error.
fn run(program: &str, args: &[&str]) -> Result<()> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("run {program}"))?;
    if !output.status.success() {
        bail!(
            "{program} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn launchd_domain() -> String {
    // SAFETY: getuid has no preconditions.
    format!("gui/{}", unsafe { libc::getuid() })
}

/// Writes the service file and starts it (now and at every login).
pub fn install(text: &str, start: bool) -> Result<PathBuf> {
    let file = service_file()?;
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    let was_running = start && is_running();
    std::fs::write(&file, text).with_context(|| format!("write {}", file.display()))?;
    if !start {
        return Ok(file);
    }
    if cfg!(target_os = "macos") {
        let domain = launchd_domain();
        // Reinstalling replaces the one loaded before.
        let _ = run("launchctl", &["bootout", &format!("{domain}/{LABEL}")]);
        run(
            "launchctl",
            &["bootstrap", &domain, &file.to_string_lossy()],
        )?;
    } else {
        run("systemctl", &["--user", "daemon-reload"])?;
        run("systemctl", &["--user", "enable", UNIT])?;
        let action = if was_running { "restart" } else { "start" };
        run("systemctl", &["--user", action, UNIT])?;
    }
    Ok(file)
}

/// Stops the service and removes its file; false when it was not installed.
pub fn uninstall() -> Result<bool> {
    let file = service_file()?;
    if !file.exists() {
        return Ok(false);
    }
    if cfg!(target_os = "macos") {
        let _ = run(
            "launchctl",
            &["bootout", &format!("{}/{LABEL}", launchd_domain())],
        );
    } else {
        let _ = run("systemctl", &["--user", "disable", "--now", UNIT]);
    }
    std::fs::remove_file(&file).with_context(|| format!("remove {}", file.display()))?;
    if !cfg!(target_os = "macos") {
        let _ = run("systemctl", &["--user", "daemon-reload"]);
    }
    Ok(true)
}

/// Whether the service manager runs it now.
pub fn is_running() -> bool {
    if cfg!(target_os = "macos") {
        std::process::Command::new("launchctl")
            .args(["print", &format!("{}/{LABEL}", launchd_domain())])
            .output()
            .is_ok_and(|out| {
                out.status.success()
                    && String::from_utf8_lossy(&out.stdout).contains("state = running")
            })
    } else {
        std::process::Command::new("systemctl")
            .args(["--user", "is-active", "--quiet", UNIT])
            .status()
            .is_ok_and(|status| status.success())
    }
}

/// The `kutup ssh-agent …` command line an installed service file runs.
pub fn installed_arguments(text: &str) -> Option<Vec<String>> {
    if let Some(line) = text
        .lines()
        .find_map(|line| line.strip_prefix("ExecStart="))
    {
        return Some(systemd_words(line));
    }
    let start = text.find("<array>")?;
    let end = text[start..].find("</array>")? + start;
    Some(
        text[start..end]
            .split("<string>")
            .skip(1)
            .filter_map(|part| part.split("</string>").next())
            .map(|word| {
                word.replace("&lt;", "<")
                    .replace("&gt;", ">")
                    .replace("&quot;", "\"")
                    .replace("&apos;", "'")
                    .replace("&amp;", "&")
            })
            .collect(),
    )
}

/// Splits what `systemd_quote` wrote back into words.
fn systemd_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut chars = line.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c == ' ' {
            chars.next();
            continue;
        }
        let mut word = String::new();
        if c == '"' {
            chars.next();
            while let Some(c) = chars.next() {
                match c {
                    '"' => break,
                    '\\' => match chars.next() {
                        Some('n') => word.push('\n'),
                        Some(other) => word.push(other),
                        None => {}
                    },
                    '%' | '$' if chars.peek() == Some(&c) => {
                        chars.next();
                        word.push(c);
                    }
                    c => word.push(c),
                }
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c == ' ' {
                    break;
                }
                word.push(c);
                chars.next();
            }
        }
        words.push(word);
    }
    words
}

/// The value after `flag` in an agent command line.
pub fn flag_value<'a>(arguments: &'a [String], flag: &str) -> Option<&'a str> {
    arguments
        .iter()
        .position(|a| a == flag)
        .and_then(|i| arguments.get(i + 1))
        .map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> Service {
        Service {
            program: "/home/ayşe/bin/kutup".into(),
            profile: "default".into(),
            local_dir: "/home/ayşe/Kasa \"iş\" 100%$HOME\\x".into(),
            collection_id: "c0ffee".into(),
            socket: "/run/user/1000/kutup/ssh-agent.sock".into(),
            idle: 15,
            no_confirm: false,
            environment: Vec::new(),
        }
    }

    #[test]
    fn the_unit_runs_the_agent_asking_on_the_desktop() {
        let unit = service().systemd_unit();
        assert!(unit.contains("WantedBy=default.target"));
        assert!(unit.contains("Restart=on-failure"));
        let exec = unit.lines().find(|l| l.starts_with("ExecStart=")).unwrap();
        assert_eq!(
            exec,
            r#"ExecStart="/home/ayşe/bin/kutup" "--profile" "default" "ssh-agent" "/home/ayşe/Kasa \"iş\" 100%%$$HOME\\x" "c0ffee" "--socket" "/run/user/1000/kutup/ssh-agent.sock" "--idle" "15" "--approve" "desktop""#
        );
        assert_eq!(installed_arguments(&unit).unwrap(), service().arguments());
        assert!(!unit.contains("PASSWORD"), "no secret in the unit");
        assert!(!unit.contains("Environment="));
        let mut s = service();
        s.environment = vec![(
            "KUTUP_SSH_ASKPASS".into(),
            "/usr/lib/ssh/x11-ssh-askpass".into(),
        )];
        assert!(s
            .systemd_unit()
            .contains("Environment=\"KUTUP_SSH_ASKPASS=/usr/lib/ssh/x11-ssh-askpass\"\n"));
        assert!(s.launchd_plist(Path::new("/l")).contains(
            "<key>KUTUP_SSH_ASKPASS</key>\n    <string>/usr/lib/ssh/x11-ssh-askpass</string>"
        ));
    }

    #[test]
    fn the_plist_runs_the_same_with_its_text_escaped() {
        let mut s = service();
        s.no_confirm = true;
        s.local_dir = "/Users/a/<Kasa> & 'x'".into();
        let plist = s.launchd_plist(Path::new("/Users/a/Library/Logs/kutup-ssh-agent.log"));
        assert!(plist.contains("<string>/Users/a/&lt;Kasa&gt; &amp; &apos;x&apos;</string>"));
        assert!(plist.contains(&format!("<string>{LABEL}</string>")));
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert_eq!(installed_arguments(&plist).unwrap(), s.arguments());
        assert!(s.arguments().ends_with(&[
            "--approve".into(),
            "desktop".into(),
            "--no-confirm".into()
        ]));
    }

    #[test]
    fn flags_are_read_back() {
        let args = service().arguments();
        assert_eq!(
            flag_value(&args, "--socket"),
            Some("/run/user/1000/kutup/ssh-agent.sock")
        );
        assert_eq!(flag_value(&args, "--idle"), Some("15"));
        assert_eq!(flag_value(&args, "--nope"), None);
    }
}
