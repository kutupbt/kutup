// libsodium-wrappers-sumo singleton — sumo build required for Argon2id.
// Standard libsodium-wrappers does NOT include Argon2id.
import _sodium from 'libsodium-wrappers-sumo'

let ready = false

export async function getSodium() {
  if (!ready) {
    await _sodium.ready
    ready = true
  }
  return _sodium
}
