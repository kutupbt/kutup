#![no_main]

use kutup_chat_proto::{decode_profile_envelope, ChatProfileResponse, PutChatProfileRequest};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(encoded) = std::str::from_utf8(data) {
        let _ = decode_profile_envelope(encoded);
    }
    let _ = serde_json::from_slice::<PutChatProfileRequest>(data);
    let _ = serde_json::from_slice::<ChatProfileResponse>(data);
});
