//! Kutup address keys work with GnuPG in both directions
//! (docs/plans/mail-address-keys.md). Skipped where `gpg` is not installed.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use kutup_crypto::mail_key::{armor_public_key, decrypt, encrypt, generate_address_key};

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
fn gnupg_reads_kutup_keys_and_kutup_reads_gnupg() {
    if Command::new("gpg").arg("--version").output().is_err() {
        eprintln!("gpg not installed; skipping");
        return;
    }
    let home = std::env::temp_dir().join(format!("kutup-gnupg-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    let alice = generate_address_key("alice@kutup.dev", 1_790_000_000).unwrap();
    let bob = generate_address_key("bob@kutup.dev", 1_790_000_000).unwrap();

    // GnuPG imports Alice's public key and encrypts to her; Kutup decrypts.
    let armored = armor_public_key(&alice.public_key).unwrap();
    let (ok, _, err) = gpg(&home, &["--import"], armored.as_bytes());
    assert!(ok, "import: {err}");
    let (ok, message, err) = gpg(
        &home,
        &["--armor", "--encrypt", "-r", "alice@kutup.dev"],
        b"from gnupg",
    );
    assert!(ok, "encrypt: {err}");
    assert!(
        !err.contains("not found in recipient preferences"),
        "preferences: {err}"
    );
    let opened = decrypt(&alice.secret_key, &message, None).unwrap();
    assert_eq!(&opened.data[..], b"from gnupg");

    // Kutup encrypts to Bob, signed by Alice; GnuPG (holding Bob's secret
    // key) decrypts and reports a good signature from Alice.
    let bob_secret = kutup_crypto::mail_key::armor_secret_key_for_tests(&bob.secret_key);
    let (ok, _, err) = gpg(&home, &["--import"], bob_secret.as_bytes());
    assert!(ok, "import secret: {err}");
    let message = encrypt(&bob.public_key, Some(&alice.secret_key), b"from kutup").unwrap();
    let (ok, plaintext, err) = gpg(&home, &["--decrypt"], message.as_bytes());
    assert!(ok, "decrypt: {err}");
    assert_eq!(plaintext, b"from kutup");
    assert!(
        err.contains("Good signature from \"alice <alice@kutup.dev>\""),
        "verify: {err}"
    );

    let _ = std::fs::remove_dir_all(&home);
}
