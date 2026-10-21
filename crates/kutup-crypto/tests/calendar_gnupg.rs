//! Calendar keys and packets work with GnuPG in both directions
//! (docs/plans/calendar.md, E1): a second OpenPGP implementation reads the
//! passphrase-locked calendar key, opens Kutup's key and data packets and
//! names the same session key, and Kutup opens GnuPG's. Skipped where `gpg`
//! is not installed.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use kutup_crypto::calendar::{
    decrypt_data_packet, encrypt_data_packet, generate_calendar_key, key_packet_to,
    unlock_calendar_key, Passphrase, SessionKey,
};
use kutup_crypto::mail_key::{armor_public_key, packet_extent};

fn gpg(home: &PathBuf, args: &[&str], input: &[u8]) -> (bool, Vec<u8>, String) {
    let mut child = Command::new("gpg")
        .env("GNUPGHOME", home)
        .args(["--batch", "--yes", "--trust-model", "always"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("gpg runs");
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    (
        output.status.success(),
        output.stdout,
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn gnupg_reads_calendar_packets_and_kutup_reads_gnupg() {
    if Command::new("gpg").arg("--version").output().is_err() {
        eprintln!("gpg not installed; skipping");
        return;
    }
    let home = std::env::temp_dir().join(format!("kutup-cal-gnupg-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    let passphrase = Passphrase::generate();
    let calendar = generate_calendar_key(&passphrase, 1_790_000_000).unwrap();
    let unlock = [
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        passphrase.as_str(),
    ];

    // GnuPG imports the locked calendar key with its passphrase.
    let (ok, _, err) = gpg(
        &home,
        &[&unlock[..], &["--import"]].concat(),
        &calendar.locked_secret_key,
    );
    assert!(ok, "import: {err}");

    // Kutup's key packet and data packet, as stored apart, read together by
    // GnuPG: the same plaintext and the same session key.
    let session_key = SessionKey::generate();
    let mut message = key_packet_to(&session_key, &calendar.public_key).unwrap();
    message.extend(encrypt_data_packet(&session_key, b"BEGIN:VCALENDAR from kutup").unwrap());
    let (ok, plain, err) = gpg(
        &home,
        &[&unlock[..], &["--show-session-key", "--decrypt"]].concat(),
        &message,
    );
    assert!(ok, "decrypt: {err}");
    assert_eq!(plain, b"BEGIN:VCALENDAR from kutup");
    let expected = format!("9:{}", hex::encode_upper(session_key.as_bytes()));
    assert!(err.contains(&expected), "session key: {err}");

    // GnuPG encrypts to the calendar key (uncompressed, as Proton's data
    // packets are); Kutup opens its key packet and its data packet apart.
    let armored = armor_public_key(&calendar.public_key).unwrap();
    let (ok, _, err) = gpg(&home, &["--import"], armored.as_bytes());
    assert!(ok, "import public: {err}");
    let recipient = hex::encode_upper(calendar.fingerprint);
    let (ok, message, err) = gpg(
        &home,
        &[
            "--compress-algo",
            "none",
            "--encrypt",
            "-r",
            recipient.as_str(),
        ],
        b"BEGIN:VCALENDAR from gnupg",
    );
    assert!(ok, "encrypt: {err}");
    let (_, _, key_packet_len) = packet_extent(&message).unwrap();
    let (key_packet, data_packet) = message.split_at(key_packet_len);
    let unlocked = unlock_calendar_key(&calendar.locked_secret_key, &passphrase).unwrap();
    let opened = unlocked.open_key_packet(key_packet).unwrap();
    assert_eq!(
        decrypt_data_packet(&opened, data_packet)
            .unwrap()
            .as_slice(),
        b"BEGIN:VCALENDAR from gnupg"
    );

    let _ = std::fs::remove_dir_all(&home);
}
