// @vitest-environment node
import { describe, expect, it, vi } from 'vitest'
import vectors from '../../../../crates/kutup-crypto/tests/vectors/crypto.json'

vi.mock('./rustWasm', async () => {
  const [{ readFile }, module] = await Promise.all([
    import('node:fs/promises'),
    import('../../../wasm/crypto-wasm/kutup_crypto_wasm.js'),
  ])
  const wasm = await readFile(new URL(
    '../../../wasm/crypto-wasm/kutup_crypto_wasm_bg.wasm',
    import.meta.url,
  ))
  await module.default({ module_or_path: wasm })
  return { getCryptoWasm: async () => module }
})

import { fromBase64 } from './base64'
import { LocalStatePurpose, openLocalState, sealLocalState } from './localState'

const v = vectors.localState
const key = fromBase64(v.key)

describe('local-state envelopes', () => {
  it('open the canonical Rust vectors', async () => {
    expect(await openLocalState(v.sessionFork.envelope, key, LocalStatePurpose.SessionFork, v.sessionFork.profile))
      .toEqual(fromBase64(v.sessionFork.plaintext))
    expect(await openLocalState(v.webSession.envelope, key, LocalStatePurpose.WebSession, v.webSession.profile))
      .toEqual(fromBase64(v.webSession.plaintext))
  })

  it('round-trip with a fresh nonce', async () => {
    const plaintext = new TextEncoder().encode('{"v":1}')
    const a = await sealLocalState(plaintext, key, LocalStatePurpose.WebSession, 'web-drive:s1')
    const b = await sealLocalState(plaintext, key, LocalStatePurpose.WebSession, 'web-drive:s1')
    expect(a).not.toEqual(b)
    expect(await openLocalState(a, key, LocalStatePurpose.WebSession, 'web-drive:s1')).toEqual(plaintext)
  })

  it('fail closed on another profile, purpose or key', async () => {
    const env = v.sessionFork.envelope
    await expect(openLocalState(env, key, LocalStatePurpose.SessionFork, 'web-chat')).rejects.toBeDefined()
    await expect(openLocalState(env, key, LocalStatePurpose.WebSession, 'web-drive')).rejects.toBeDefined()
    await expect(openLocalState(env, new Uint8Array(32), LocalStatePurpose.SessionFork, 'web-drive'))
      .rejects.toBeDefined()
  })
})
