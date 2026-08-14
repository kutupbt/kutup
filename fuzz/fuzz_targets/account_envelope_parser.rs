#![no_main]

use kutup_crypto::account_envelope::{self, AccountEnvelopePurpose};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = account_envelope::inspect(data);
    for purpose in [
        AccountEnvelopePurpose::PasswordMasterKey,
        AccountEnvelopePurpose::RecoveryMasterKey,
        AccountEnvelopePurpose::DriveHpkePrivateKey,
    ] {
        let _ = account_envelope::validate(data, purpose, "fuzz@example.test", 32);
        let _ = account_envelope::open(data, &[0x5a; 32], purpose, "fuzz@example.test");
    }
});
