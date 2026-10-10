//! PGP with the rest of the world (docs/plans/mail.md, C3), against GnuPG
//! playing an outside correspondent, Dave: his key passes Kutup's checks,
//! Kutup's armored, signed messages open in GnuPG with a good signature,
//! his open in Kutup verified, and his detached and cleartext signatures
//! check. Skipped where `gpg` is not installed.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use kutup_crypto::mail_key::{
    armor_public_key, decrypt, encrypt_armored_signed, encryption_key_id, generate_address_key,
    inspect_external_public_key, pgp_message_key_ids, verify_cleartext, verify_detached,
};

const DAY: u64 = 86_400;

fn gpg(home: &Path, args: &[&str], input: &[u8]) -> (bool, Vec<u8>, String) {
    let mut child = Command::new("gpg")
        .env("GNUPGHOME", home)
        .args([
            "--batch",
            "--yes",
            "--trust-model",
            "always",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
        ])
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

fn home(name: &str) -> PathBuf {
    let home = std::env::temp_dir().join(format!("kutup-pgp-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    home
}

/// A GnuPG key for `uid` (Ed25519 signing, Curve25519 encryption) valid for
/// `days`; returns its fingerprint.
fn make_key(home: &Path, uid: &str, days: &str) -> String {
    let (ok, _, err) = gpg(
        home,
        &["--quick-gen-key", uid, "ed25519", "cert,sign", days],
        b"",
    );
    assert!(ok, "gen-key: {err}");
    let (_, listing, _) = gpg(home, &["--with-colons", "--list-keys", uid], b"");
    let fingerprint = String::from_utf8(listing)
        .unwrap()
        .lines()
        .find_map(|line| {
            line.strip_prefix("fpr:::::::::")
                .map(|f| f.trim_end_matches(':').to_string())
        })
        .expect("fingerprint");
    let (ok, _, err) = gpg(
        home,
        &["--quick-add-key", &fingerprint, "cv25519", "encr", days],
        b"",
    );
    assert!(ok, "add-key: {err}");
    fingerprint
}

fn export(home: &Path, uid: &str) -> Vec<u8> {
    let (ok, key, err) = gpg(home, &["--export", uid], b"");
    assert!(ok && !key.is_empty(), "export: {err}");
    key
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn kutup_and_gnupg_exchange_signed_encrypted_mail() {
    if Command::new("gpg").arg("--version").output().is_err() {
        eprintln!("gpg not installed; skipping");
        return;
    }
    let dave_home = home("dave");
    let dave_fpr = make_key(&dave_home, "Dave Outside <Dave@Example.org>", "1y");
    let dave_public = export(&dave_home, "dave@example.org");

    // Dave's key passes, binary or armored, only for his address.
    let info = inspect_external_public_key(&dave_public, "dave@example.org", now()).unwrap();
    assert_eq!(info.fingerprint, dave_fpr.to_lowercase());
    let (_, armored, _) = gpg(
        &dave_home,
        &["--armor", "--export", "dave@example.org"],
        b"",
    );
    assert_eq!(
        inspect_external_public_key(&armored, "DAVE@example.org", now())
            .unwrap()
            .public_key,
        info.public_key
    );
    assert!(inspect_external_public_key(&dave_public, "eve@example.org", now()).is_err());
    // A key server's answer with several keys: the usable one for the
    // address is picked out of them.
    let else_fpr = make_key(&dave_home, "Someone Else <else@example.org>", "1y");
    // Another key's certification on Dave's user ID (Proton certifies its
    // users' keys so) does not make the key unusable.
    let (ok, _, err) = gpg(
        &dave_home,
        &["-u", &else_fpr, "--quick-sign-key", &dave_fpr],
        b"",
    );
    assert!(ok, "certify: {err}");
    let certified = export(&dave_home, &dave_fpr);
    assert_eq!(
        inspect_external_public_key(&certified, "dave@example.org", now())
            .unwrap()
            .fingerprint,
        info.fingerprint
    );
    let (_, both, _) = gpg(&dave_home, &["--export"], b"");
    let picked =
        kutup_crypto::mail_key::inspect_external_public_keys(&both, "dave@example.org", now())
            .unwrap();
    assert_eq!(picked.fingerprint, info.fingerprint);
    assert!(
        kutup_crypto::mail_key::inspect_external_public_keys(&both, "eve@example.org", now())
            .is_err()
    );
    // A year on, it has expired.
    assert!(
        inspect_external_public_key(&dave_public, "dave@example.org", now() + 400 * DAY).is_err()
    );
    // Described as it is, expired or not.
    let described = kutup_crypto::mail_key::describe_external_public_key(&armored).unwrap();
    assert_eq!(described.fingerprint, info.fingerprint);
    assert_eq!(described.public_key, info.public_key);

    // Kutup (Alice) writes to Dave: GnuPG opens it and checks her signature.
    let alice = generate_address_key("alice@kutup.dev", 1_790_000_000).unwrap();
    let (ok, _, err) = gpg(
        &dave_home,
        &["--import"],
        armor_public_key(&alice.public_key).unwrap().as_bytes(),
    );
    assert!(ok, "import alice: {err}");
    let message = encrypt_armored_signed(
        &[&info.public_key, &alice.public_key],
        &alice.secret_key,
        b"Content-Type: text/plain\r\n\r\nMerhaba Dave\r\n",
        now(),
    )
    .unwrap();
    assert!(message.starts_with("-----BEGIN PGP MESSAGE-----"));
    let (ok, plaintext, err) = gpg(&dave_home, &["--decrypt"], message.as_bytes());
    assert!(ok, "dave decrypts: {err}");
    assert_eq!(
        plaintext,
        b"Content-Type: text/plain\r\n\r\nMerhaba Dave\r\n"
    );
    assert!(
        err.contains("Good signature from \"alice <alice@kutup.dev>\""),
        "verify: {err}"
    );
    // Alice's own copy opens with her key.
    assert!(decrypt(&alice.secret_key, message.as_bytes(), None).is_ok());
    // A server sees whom it is for, without opening it.
    let mut ids = pgp_message_key_ids(message.as_bytes()).unwrap();
    ids.sort();
    let mut expected = vec![
        encryption_key_id(&info.public_key).unwrap(),
        encryption_key_id(&alice.public_key).unwrap(),
    ];
    expected.sort();
    assert_eq!(ids, expected);
    assert!(pgp_message_key_ids(b"Content-Type: text/plain\r\n\r\nhi").is_err());
    assert!(pgp_message_key_ids(&dave_public).is_err());

    // Dave writes to Alice, signed: Kutup opens it and verifies Dave.
    let (ok, encrypted, err) = gpg(
        &dave_home,
        &[
            "--armor",
            "--sign",
            "--encrypt",
            "-r",
            "alice@kutup.dev",
            "-u",
            "dave@example.org",
        ],
        b"from dave",
    );
    assert!(ok, "dave encrypts: {err}");
    assert_eq!(
        pgp_message_key_ids(&encrypted).unwrap(),
        vec![encryption_key_id(&alice.public_key).unwrap()]
    );
    let opened = decrypt(&alice.secret_key, &encrypted, Some(&info.public_key)).unwrap();
    assert_eq!(&*opened.data, b"from dave");
    assert!(opened.signed && opened.verified);
    let other = generate_address_key("eve@kutup.dev", 1_790_000_000).unwrap();
    let opened = decrypt(&alice.secret_key, &encrypted, Some(&other.public_key)).unwrap();
    assert!(opened.signed && !opened.verified);

    // A detached signature, as in multipart/signed.
    let content = b"Content-Type: text/plain\r\n\r\nsigned, not encrypted\r\n";
    let (ok, signature, err) = gpg(
        &dave_home,
        &["--armor", "--detach-sign", "-u", "dave@example.org"],
        content,
    );
    assert!(ok, "detach-sign: {err}");
    assert!(verify_detached(&signature, content, &info.public_key).unwrap());
    assert!(!verify_detached(&signature, b"changed", &info.public_key).unwrap());
    assert!(!verify_detached(&signature, content, &other.public_key).unwrap());

    // A cleartext-signed message.
    let (ok, clear, err) = gpg(
        &dave_home,
        &["--clearsign", "-u", "dave@example.org"],
        b"Merhaba\n",
    );
    assert!(ok, "clearsign: {err}");
    let (text, verified) =
        verify_cleartext(std::str::from_utf8(&clear).unwrap(), Some(&info.public_key)).unwrap();
    assert_eq!(text.trim_end(), "Merhaba");
    assert!(verified);
    let tampered = String::from_utf8(clear)
        .unwrap()
        .replace("Merhaba", "Merhabb");
    assert!(
        !verify_cleartext(&tampered, Some(&info.public_key))
            .unwrap()
            .1
    );

    // A revoked user ID no longer vouches for its address (the other one
    // still does), and a revoked key is refused outright.
    let (ok, _, err) = gpg(
        &dave_home,
        &[
            "--quick-add-uid",
            &dave_fpr,
            "Dave Work <dave@work.example>",
        ],
        b"",
    );
    assert!(ok, "add uid: {err}");
    let (ok, _, err) = gpg(
        &dave_home,
        &[
            "--quick-revoke-uid",
            &dave_fpr,
            "Dave Work <dave@work.example>",
        ],
        b"",
    );
    assert!(ok, "revoke uid: {err}");
    let partly = export(&dave_home, &dave_fpr);
    assert!(inspect_external_public_key(&partly, "dave@work.example", now()).is_err());
    assert!(inspect_external_public_key(&partly, "dave@example.org", now()).is_ok());
    // GnuPG writes a revocation certificate when it makes a key, its first
    // line guarded by a colon against importing it by mistake.
    let certificate = std::fs::read_to_string(
        dave_home
            .join("openpgp-revocs.d")
            .join(format!("{dave_fpr}.rev")),
    )
    .unwrap();
    let certificate = certificate.replace(
        ":-----BEGIN PGP PUBLIC KEY BLOCK-----",
        "-----BEGIN PGP PUBLIC KEY BLOCK-----",
    );
    let (ok, _, err) = gpg(&dave_home, &["--import"], certificate.as_bytes());
    assert!(ok, "import revocation: {err}");
    let revoked = export(&dave_home, &dave_fpr);
    assert!(inspect_external_public_key(&revoked, "dave@example.org", now()).is_err());

    let _ = std::fs::remove_dir_all(&dave_home);
}
