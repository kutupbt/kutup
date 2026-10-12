//! A destination's names, from the host key OpenSSH bound the session to and
//! the user's `known_hosts` (hashed entries cannot be read back).

use base64::Engine as _;

fn files() -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Some(home) = dirs::home_dir() {
        out.push(home.join(".ssh/known_hosts"));
    }
    out.push("/etc/ssh/ssh_known_hosts".into());
    out
}

/// Host names whose known key is `host_key` (a public key blob).
pub fn names_for(host_key: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    for file in files() {
        if let Ok(text) = std::fs::read_to_string(file) {
            names.extend(names_in(&text, host_key));
        }
    }
    names.sort();
    names.dedup();
    names
}

pub fn names_in(text: &str, host_key: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('@') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let (Some(hosts), Some(_kind), Some(key)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if hosts.starts_with('|') {
            continue;
        }
        if base64::engine::general_purpose::STANDARD
            .decode(key)
            .ok()
            .as_deref()
            == Some(host_key)
        {
            names.extend(
                hosts
                    .split(',')
                    .filter(|h| !h.starts_with('!'))
                    .map(str::to_owned),
            );
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_entries_name_the_host_and_hashed_ones_are_skipped() {
        let key = b"host key blob";
        let b64 = base64::engine::general_purpose::STANDARD.encode(key);
        let text = format!(
            "# comment\ngithub.com,140.82.121.4 ssh-ed25519 {b64}\n|1|salt|hash ssh-ed25519 {b64}\nother.example ssh-ed25519 AAAA\n@revoked bad.example ssh-ed25519 {b64}\n"
        );
        assert_eq!(names_in(&text, key), ["github.com", "140.82.121.4"]);
    }
}
