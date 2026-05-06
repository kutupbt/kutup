// @vitest-environment node
import { describe, it, expect } from 'vitest'
import _sodium from 'libsodium-wrappers-sumo'
import { encryptYjsUpdate, decryptYjsUpdate, deriveContentKey } from './cryptoFrame'

describe('cryptoFrame', () => {
  it('encrypt then decrypt round-trips a Yjs update', async () => {
    await _sodium.ready
    const fileId = '00000000-0000-0000-0000-000000000001'
    const masterKey = _sodium.randombytes_buf(32)
    const update = new TextEncoder().encode('test yjs update bytes')
    const f = await encryptYjsUpdate(update, fileId, 1, 1n, 1n, masterKey)
    const out = await decryptYjsUpdate(f, fileId, masterKey)
    expect(new TextDecoder().decode(out)).toBe('test yjs update bytes')
  })
  it('deriveContentKey is deterministic per (collection, fileId)', async () => {
    await _sodium.ready
    const m = _sodium.randombytes_buf(32)
    const k1 = await deriveContentKey(m, 'abc')
    const k2 = await deriveContentKey(m, 'abc')
    expect(Array.from(k1)).toEqual(Array.from(k2))
  })
  it('different fileIds produce different keys', async () => {
    await _sodium.ready
    const m = _sodium.randombytes_buf(32)
    const k1 = await deriveContentKey(m, 'abc')
    const k2 = await deriveContentKey(m, 'def')
    expect(Array.from(k1)).not.toEqual(Array.from(k2))
  })
  it('decrypting with wrong masterKey fails', async () => {
    await _sodium.ready
    const fileId = 'file-1'
    const m1 = _sodium.randombytes_buf(32)
    const m2 = _sodium.randombytes_buf(32)
    const update = new TextEncoder().encode('payload')
    const f = await encryptYjsUpdate(update, fileId, 1, 1n, 1n, m1)
    await expect(decryptYjsUpdate(f, fileId, m2)).rejects.toThrow()
  })
})
