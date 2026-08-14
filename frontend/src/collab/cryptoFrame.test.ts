// @vitest-environment node
import { describe, expect, it, vi } from 'vitest'

vi.mock('@/crypto/rustWasm', async () => {
  const [{ readFile }, module] = await Promise.all([
    import('node:fs/promises'),
    import('../../public/crypto-wasm/kutup_crypto_wasm.js'),
  ])
  const wasm = await readFile(new URL(
    '../../public/crypto-wasm/kutup_crypto_wasm_bg.wasm',
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
  collectionId: '22222222-2222-4222-8222-222222222222',
  keyEpoch: 3,
}

async function fixture() {
  const keypair = await generateDeviceKeypair()
  const collectionKey = new Uint8Array(32).fill(0x41)
  const plaintext = new TextEncoder().encode('canonical collaboration update')
  const frame = await encryptCollabFrameV1(
    plaintext,
    KIND.YJS_UPDATE,
    { ...binding, docKeyId: 7, deviceId: 42n, sequence: 9n },
    collectionKey,
    keypair.privateKey,
  )
  return { collectionKey, frame, plaintext }
}

describe('canonical collaboration frame', () => {
  it('round-trips through the Rust/WASM suite', async () => {
    const { collectionKey, frame, plaintext } = await fixture()
    const opened = await openCollabFrameV1(frame, collectionKey, binding)
    expect(opened.plaintext).toEqual(plaintext)
    expect(opened.kind).toBe(KIND.YJS_UPDATE)
    expect(opened.keyEpoch).toBe(3)
    expect(opened.docKeyId).toBe(7)
    expect(opened.senderDeviceId).toBe(42n)
    expect(opened.sequence).toBe(9n)
  })

  it('rejects a wrong collection key and ciphertext tampering', async () => {
    const { collectionKey, frame } = await fixture()
    await expect(openCollabFrameV1(
      frame,
      new Uint8Array(32).fill(0x42),
      binding,
    )).rejects.toThrow()

    const tampered = frame.slice()
    tampered[100] ^= 0x80
    await expect(openCollabFrameV1(tampered, collectionKey, binding)).rejects.toThrow()
  })

  it('rejects file, collection, and epoch relocation', async () => {
    const { collectionKey, frame } = await fixture()
    await expect(openCollabFrameV1(frame, collectionKey, {
      ...binding,
      fileId: '33333333-3333-4333-8333-333333333333',
    })).rejects.toThrow()
    await expect(openCollabFrameV1(frame, collectionKey, {
      ...binding,
      collectionId: '44444444-4444-4444-8444-444444444444',
    })).rejects.toThrow()
    await expect(openCollabFrameV1(frame, collectionKey, {
      ...binding,
      keyEpoch: binding.keyEpoch + 1,
    })).rejects.toThrow()
  })

  it('rejects an unknown suite before decryption', async () => {
    const { collectionKey, frame } = await fixture()
    const unknownSuite = frame.slice()
    unknownSuite[8] = 0x7f
    unknownSuite[9] = 0xff
    await expect(openCollabFrameV1(unknownSuite, collectionKey, binding)).rejects.toThrow()
  })
})
