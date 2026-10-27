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

import { toBase64 } from '@kutup/crypto/base64'
import { getCryptoWasm } from '@kutup/crypto/rustWasm'
import { generateSigningKey } from '@kutup/crypto/signing'
import { encryptCollabFrame, openCollabFrame, openCollabFrameAtGeneration } from './cryptoFrame'
import { KIND, peerKey } from './envelope'

const binding = {
  fileId: '11111111-1111-4111-8111-111111111111',
  keyGeneration: 3,
}
const SERVER = 'kutup.example'
const ACCOUNT_ID = '22222222-2222-4222-8222-222222222222'
const ACCOUNT = `aci:${ACCOUNT_ID}@${SERVER}`

/**
 * What a server delivers (Rust `envelope::deliver`): the sender's
 * `AccountRef::bytes` (the server's length, u16 big-endian, the server, the
 * account id's 16 bytes), then the packed frame.
 */
function delivered(frame: Uint8Array, server = SERVER, accountId = ACCOUNT_ID): Uint8Array {
  const name = new TextEncoder().encode(server)
  const id = Uint8Array.from(accountId.replace(/-/g, '').match(/../g)!.map((h) => parseInt(h, 16)))
  const out = new Uint8Array(2 + name.length + id.length + frame.length)
  out[0] = name.length >> 8
  out[1] = name.length & 0xff
  out.set(name, 2)
  out.set(id, 2 + name.length)
  out.set(frame, 2 + name.length + id.length)
  return out
}

async function fixture() {
  const keypair = await generateSigningKey()
  const fileKey = new Uint8Array(32).fill(0x41)
  const plaintext = new TextEncoder().encode('canonical collaboration update')
  const frame = await encryptCollabFrame(
    plaintext,
    KIND.YJS_UPDATE,
    { ...binding, docKeyId: 7, sequence: 9n },
    fileKey,
    { deviceId: 42, account: ACCOUNT, manifestSequence: 5n, keypair },
  )
  return { fileKey, frame, plaintext, keypair }
}

describe('canonical collaboration frame', () => {
  it('round-trips through the Rust/WASM suite as a server delivers it', async () => {
    const { fileKey, frame, plaintext } = await fixture()
    const opened = await openCollabFrame(delivered(frame), fileKey, binding)
    expect(opened.plaintext).toEqual(plaintext)
    expect(opened.sender).toBe(ACCOUNT)
    expect(opened.kind).toBe(KIND.YJS_UPDATE)
    expect(opened.keyGeneration).toBe(3)
    expect(opened.docKeyId).toBe(7)
    expect(opened.deviceId).toBe(42)
    expect(opened.manifestSequence).toBe(5n)
    expect(opened.sequence).toBe(9n)
    expect(peerKey(opened.sender, opened.deviceId)).toBe(`${ACCOUNT}#42`)
  })

  it('is signed under its sender account', async () => {
    const { frame, keypair } = await fixture()
    const module = await getCryptoWasm()
    const key = toBase64(keypair.publicKey)
    expect(module.verifyCollabFrame(toBase64(frame), ACCOUNT, key)).toBe(true)
    // A server naming another sender breaks the signature.
    expect(module.verifyCollabFrame(toBase64(frame), `aci:${ACCOUNT_ID}@other.example`, key)).toBe(false)
  })

  it('refuses a bare frame where a delivered one belongs', async () => {
    const { fileKey, frame } = await fixture()
    await expect(openCollabFrame(frame, fileKey, binding)).rejects.toThrow()
  })

  it('opens a frame with the key of the generation it names', async () => {
    const { fileKey, frame } = await fixture()
    const keyAt = async (generation: number) => {
      expect(generation).toBe(3)
      return fileKey
    }
    const opened = await openCollabFrameAtGeneration(delivered(frame), keyAt, { ...binding, keyGeneration: 4 })
    expect(opened.keyGeneration).toBe(3)
    await expect(openCollabFrameAtGeneration(delivered(frame), keyAt, { ...binding, keyGeneration: 2 })).rejects.toThrow()
  })

  it('rejects a wrong file key and ciphertext tampering', async () => {
    const { fileKey, frame } = await fixture()
    await expect(openCollabFrame(
      delivered(frame),
      new Uint8Array(32).fill(0x42),
      binding,
    )).rejects.toThrow()

    const tampered = frame.slice()
    tampered[100] ^= 0x80
    await expect(openCollabFrame(delivered(tampered), fileKey, binding)).rejects.toThrow()
  })

  it('rejects file and key-generation relocation', async () => {
    const { fileKey, frame } = await fixture()
    await expect(openCollabFrame(delivered(frame), fileKey, {
      ...binding,
      fileId: '33333333-3333-4333-8333-333333333333',
    })).rejects.toThrow()
    await expect(openCollabFrame(delivered(frame), fileKey, {
      ...binding,
      keyGeneration: binding.keyGeneration + 1,
    })).rejects.toThrow()
  })

  it('rejects an unknown suite before decryption', async () => {
    const { fileKey, frame } = await fixture()
    const unknownSuite = frame.slice()
    unknownSuite[8] = 0x7f
    unknownSuite[9] = 0xff
    await expect(openCollabFrame(delivered(unknownSuite), fileKey, binding)).rejects.toThrow()
  })
})
