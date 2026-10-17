// The recovery path's derivation. All construction, labels, validation and
// policy live in the canonical Rust kutup-crypto crate; this module is only a
// browser transport adapter. The password path is OPAQUE (./opaqueWorker).

import { getCryptoWasm } from './rustWasm'

export async function deriveRecoveryAuthProof(
  recoveryEntropyBase64: string,
  binding: string,
): Promise<string> {
  const module = await getCryptoWasm()
  return module.deriveRecoveryAuthProof(recoveryEntropyBase64, binding)
}
