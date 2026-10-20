//! What a run does: how many virtual users, how fast they arrive, for how
//! long, and how often each one does each thing. Read from a TOML file
//! (`scenarios/*.toml`); every field has a default.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Scenario {
    /// Active virtual users: each signs up, signs in, opens Chat and does the
    /// mix below.
    pub users: usize,
    /// Users arrive evenly over this many seconds.
    pub ramp_secs: u64,
    /// How long the mix runs once the last user arrived.
    pub duration_secs: u64,
    /// Extra signed-in users that only hold a Chat WebSocket open.
    pub idle_sockets: usize,
    /// Idle sockets arrive evenly over this many seconds.
    pub idle_ramp_secs: u64,
    /// OS threads for Chat engines (each runs many users on one task set).
    pub chat_threads: usize,
    /// Report every this many seconds while running.
    pub report_every_secs: u64,
    pub mix: Mix,
    pub drive: Drive,
}

/// How often each active user does each thing, per minute (a Poisson rate).
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Mix {
    /// A session refresh (`POST /api/auth/refresh`).
    pub refresh: f64,
    /// A full OPAQUE sign-in again (a new tab, a new day).
    pub sign_in: f64,
    pub drive_upload: f64,
    pub drive_download: f64,
    pub drive_list: f64,
    /// A text to the user's chat partner.
    pub chat_text: f64,
    /// A typing indicator to the partner (typing starts).
    pub chat_typing: f64,
    pub mail_send: f64,
    pub mail_list: f64,
    /// Open (download and decrypt) the newest message in the inbox.
    pub mail_open: f64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Drive {
    /// File sizes in KiB, chosen by `weights`.
    pub sizes_kib: Vec<u64>,
    pub weights: Vec<u32>,
}

impl Default for Scenario {
    fn default() -> Self {
        Scenario {
            users: 50,
            ramp_secs: 60,
            duration_secs: 300,
            idle_sockets: 0,
            idle_ramp_secs: 60,
            chat_threads: 4,
            report_every_secs: 10,
            mix: Mix::default(),
            drive: Drive::default(),
        }
    }
}

/// A busy user's minute, roughly: chatting most, Drive and Mail now and
/// then. Receipts aren't in the mix: every received text is answered with a
/// delivery and a read receipt, as the apps do.
impl Default for Mix {
    fn default() -> Self {
        Mix {
            refresh: 0.07,
            sign_in: 0.01,
            drive_upload: 0.2,
            drive_download: 0.4,
            drive_list: 1.0,
            chat_text: 2.0,
            chat_typing: 2.0,
            mail_send: 0.1,
            mail_list: 0.5,
            mail_open: 0.3,
        }
    }
}

impl Default for Drive {
    fn default() -> Self {
        Drive {
            sizes_kib: vec![16, 256, 2048, 12 * 1024],
            weights: vec![50, 30, 15, 5],
        }
    }
}

impl Scenario {
    pub fn load(path: Option<&std::path::Path>) -> anyhow::Result<Self> {
        let scenario: Scenario = match path {
            Some(path) => toml::from_str(&std::fs::read_to_string(path)?)?,
            None => Scenario::default(),
        };
        anyhow::ensure!(
            scenario.drive.sizes_kib.len() == scenario.drive.weights.len()
                && !scenario.drive.weights.is_empty(),
            "drive.sizes_kib and drive.weights need one weight per size"
        );
        anyhow::ensure!(scenario.chat_threads > 0, "chat_threads must be at least 1");
        Ok(scenario)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_scenarios_parse() {
        for name in ["smoke", "steady", "sockets"] {
            let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join(format!("../../tests/load/scenarios/{name}.toml"));
            Scenario::load(Some(&path)).unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }

    #[test]
    fn sizes_need_a_weight_each() {
        let mut scenario = Scenario::default();
        scenario.drive.weights.pop();
        let text = format!(
            "[drive]\nsizes_kib = {:?}\nweights = {:?}\n",
            scenario.drive.sizes_kib, scenario.drive.weights
        );
        let path = std::env::temp_dir().join(format!("kutup-load-{}.toml", std::process::id()));
        std::fs::write(&path, text).unwrap();
        assert!(Scenario::load(Some(&path)).is_err());
        let _ = std::fs::remove_file(path);
    }
}
