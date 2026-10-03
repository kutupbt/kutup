// Typed adapter for kutup-crypto's local-state envelopes, the two purposes a
// web page may use (see crates/kutup-crypto/src/local_state.rs):
//
// - SessionFork: the key payload the account app hands drive/chat during a
//   session fork. Profile = the child client type ('web-drive' | 'web-chat').
// - WebSession: an app's persisted session keys in localStorage, sealed under
//   a per-session key only the server holds. Profile = `<client>:<session id>`.
//
// The format (suite, header, nonce, AEAD) is owned by Rust; this file only
// converts types.

import { fromBase64, toBase64 } from './base64'
import { getCryptoWasm } from './rustWasm'

export const LocalStatePurpose = {
  SessionFork: 2,
  WebSession: 3,
} as const
export type LocalStatePurpose = (typeof LocalStatePurpose)[keyof typeof LocalStatePurpose]

export async function sealLocalState(
  plaintext: Uint8Array,
  key: Uint8Array,
  purpose: LocalStatePurpose,
  profile: string,
): Promise<string> {
  const wasm = await getCryptoWasm()
  return wasm.sealLocalState(toBase64(plaintext), toBase64(key), purpose, profile)
}

/** Throws when the key, purpose or profile does not match, or the envelope was altered. */
export async function openLocalState(
  envelope: string,
  key: Uint8Array,
  purpose: LocalStatePurpose,
  profile: string,
): Promise<Uint8Array> {
  const wasm = await getCryptoWasm()
  return fromBase64(wasm.openLocalState(envelope, toBase64(key), purpose, profile))
}
