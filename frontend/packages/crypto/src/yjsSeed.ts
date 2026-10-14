// The Yjs client id a file's first content is made under
// (crates/kutup-crypto/src/yjs_seed.rs, which owns the format).

import { getCryptoWasm } from './rustWasm'

/**
 * The seed's client id, from the file id and the seed's own update made under
 * client id 0: the same content gives the same id on every peer, different
 * content a different one.
 */
export async function yjsSeedClientId(fileId: string, content: Uint8Array): Promise<number> {
  const wasm = await getCryptoWasm()
  return wasm.yjsSeedClientId(fileId, content)
}
