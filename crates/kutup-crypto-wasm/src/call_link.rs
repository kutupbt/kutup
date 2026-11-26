//! Making and changing a meeting link (docs/plans/calendar.md, E5c), for the
//! Calendar app: the same functions, under the same names, as Chat's engine
//! runtime exports, so the shared browser code calls either. Only what a
//! link's owner needs to make one and change its title and time; joining a
//! meeting stays in Chat.

use kutup_crypto::chat_call_link as crypto;
use serde::Serialize;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::calendar::{crypto_error, from_js, to_js};

/// The owner's call-link root (standard base64 of 32 bytes).
fn root(base64: &str) -> Result<kutup_crypto::account_roots::CallLinkRoot, JsValue> {
    use base64::Engine as _;
    let bytes = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(base64)
            .map_err(|_| crate::js_error("the call-link root is not base64"))?,
    );
    kutup_crypto::account_roots::CallLinkRoot::from_slice(&bytes).map_err(crypto_error)
}

#[wasm_bindgen(js_name = callLinkNonce)]
pub fn call_link_nonce() -> String {
    crypto::new_call_link_nonce()
}

#[wasm_bindgen(js_name = callLinkOwnerSecret)]
pub fn call_link_owner_secret(call_link_root: String, nonce: String) -> Result<String, JsValue> {
    let call_link_root = Zeroizing::new(call_link_root);
    crypto::owner_call_link_secret(&root(&call_link_root)?, &nonce)
        .map(|secret| secret.to_string())
        .map_err(crypto_error)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HostToken {
    host_token: String,
    host_token_hash: String,
}

#[wasm_bindgen(js_name = callLinkHostToken)]
pub fn call_link_host_token(call_link_root: String, nonce: String) -> Result<JsValue, JsValue> {
    let call_link_root = Zeroizing::new(call_link_root);
    let token = crypto::owner_call_link_host_token(&root(&call_link_root)?, &nonce)
        .map_err(crypto_error)?;
    let hash = crypto::call_link_token_hash(&token).map_err(crypto_error)?;
    to_js(&HostToken {
        host_token: token.to_string(),
        host_token_hash: hash,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Keys {
    room_id: String,
    access_token: String,
    access_token_hash: String,
    frame_key: String,
}

#[wasm_bindgen(js_name = callLinkKeys)]
pub fn call_link_keys(secret: String) -> Result<JsValue, JsValue> {
    let secret = Zeroizing::new(secret);
    let keys = crypto::CallLinkKeys::derive(&secret).map_err(crypto_error)?;
    to_js(&Keys {
        room_id: keys.room_id.clone(),
        access_token: keys.access_token.clone(),
        access_token_hash: keys.access_token_hash.clone(),
        frame_key: keys.frame_key.to_string(),
    })
}

#[wasm_bindgen(js_name = callLinkFragment)]
pub fn call_link_fragment(secret: String) -> Result<String, JsValue> {
    let secret = Zeroizing::new(secret);
    crypto::call_link_fragment(&secret).map_err(crypto_error)
}

#[wasm_bindgen(js_name = callLinkParse)]
pub fn call_link_parse(fragment: String) -> Result<String, JsValue> {
    crypto::parse_call_link_fragment(&fragment)
        .map(|secret| secret.to_string())
        .map_err(crypto_error)
}

#[wasm_bindgen(js_name = callLinkSealInfo)]
pub fn call_link_seal_info(secret: String, info: JsValue) -> Result<String, JsValue> {
    let secret = Zeroizing::new(secret);
    let info: crypto::CallLinkInfoV1 = from_js(info, "meeting info")?;
    crypto::CallLinkKeys::derive(&secret)
        .and_then(|keys| keys.seal_info(&info))
        .map_err(crypto_error)
}

#[wasm_bindgen(js_name = callLinkOpenInfo)]
pub fn call_link_open_info(secret: String, sealed: String) -> Result<JsValue, JsValue> {
    let secret = Zeroizing::new(secret);
    let info = crypto::CallLinkKeys::derive(&secret)
        .and_then(|keys| keys.open_info(&sealed))
        .map_err(crypto_error)?;
    to_js(&info)
}
