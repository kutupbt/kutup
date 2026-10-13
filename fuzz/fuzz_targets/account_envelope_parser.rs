#![no_main]

use kutup_crypto::account_envelope::{self, AccountEnvelopePurpose, ObjectPolicy};
use libfuzzer_sys::fuzz_target;

/// A key binding: envelopes bind one (a lowercase UUID v4), never an address.
const BINDING: &str = "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";

fuzz_target!(|data: &[u8]| {
    let _ = account_envelope::inspect(data);
    for purpose in AccountEnvelopePurpose::ALL {
        let object = match purpose.policy().object {
            ObjectPolicy::None => vec![],
            ObjectPolicy::Required(len) => vec![0x3f; len],
        };
        let _ = account_envelope::validate_for(data, purpose, BINDING, &object);
        if purpose.policy().mutable {
            let _ = account_envelope::open_revision(data, &[0x5a; 32], purpose, BINDING, &object);
        } else {
            let _ = account_envelope::open_object(data, &[0x5a; 32], purpose, BINDING, &object);
        }
    }
});
