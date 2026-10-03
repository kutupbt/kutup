// @vitest-environment node
import { describe, expect, it, vi } from 'vitest'

vi.mock('@kutup/crypto/rustWasm', async () => {
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

import { encryptCollabFrameV1, openCollabFrameV1 } from './cryptoFrame'
import { generateDeviceKeypair } from './devices'
import { KIND } from './envelope'

const binding = {
  fileId: '11111111-1111-4111-8111-111111111111',
  keyGeneration: 3,
}

async function fixture() {
  const keypair = await generateDeviceKeypair()
  const fileKey = new Uint8Array(32).fill(0x41)
  const plaintext = new TextEncoder().encode('canonical collaboration update')
  const frame = await encryptCollabFrameV1(
    plaintext,
    KIND.YJS_UPDATE,
    { ...binding, docKeyId: 7, deviceId: 42n, sequence: 9n },
    fileKey,
    keypair.privateKey,
  )
  return { fileKey, frame, plaintext }
}

describe('canonical collaboration frame', () => {
  it('round-trips through the Rust/WASM suite', async () => {
    const { fileKey, frame, plaintext } = await fixture()
    const opened = await openCollabFrameV1(frame, fileKey, binding)
    expect(opened.plaintext).toEqual(plaintext)
    expect(opened.kind).toBe(KIND.YJS_UPDATE)
    expect(opened.keyGeneration).toBe(3)
    expect(opened.docKeyId).toBe(7)
    expect(opened.senderDeviceId).toBe(42n)
    expect(opened.sequence).toBe(9n)
  })

  it('rejects a wrong file key and ciphertext tampering', async () => {
    const { fileKey, frame } = await fixture()
    await expect(openCollabFrameV1(
      frame,
      new Uint8Array(32).fill(0x42),
      binding,
    )).rejects.toThrow()

    const tampered = frame.slice()
    tampered[100] ^= 0x80
    await expect(openCollabFrameV1(tampered, fileKey, binding)).rejects.toThrow()
  })

  it('rejects file and key-generation relocation', async () => {
    const { fileKey, frame } = await fixture()
    await expect(openCollabFrameV1(frame, fileKey, {
      ...binding,
      fileId: '33333333-3333-4333-8333-333333333333',
    })).rejects.toThrow()
    await expect(openCollabFrameV1(frame, fileKey, {
      ...binding,
      keyGeneration: binding.keyGeneration + 1,
    })).rejects.toThrow()
  })

  it('rejects an unknown suite before decryption', async () => {
    const { fileKey, frame } = await fixture()
    const unknownSuite = frame.slice()
    unknownSuite[8] = 0x7f
    unknownSuite[9] = 0xff
    await expect(openCollabFrameV1(unknownSuite, fileKey, binding)).rejects.toThrow()
  })
})
