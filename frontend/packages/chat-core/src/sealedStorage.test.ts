import { beforeEach, describe, expect, it } from 'vitest'
import { SealedStorage } from './sealedStorage'

const wasm = {
  // Stands in for the Rust sealing: reversible, and bound to scope and
  // purpose the way the real AEAD is.
  sealLocalData: (_key: Uint8Array, scope: string, purposes: string[], plains: Uint8Array[]) =>
    plains.map((plain, i) => new TextEncoder().encode(`${scope}|${purposes[i]}|${btoa(String.fromCharCode(...plain))}`)),
  openLocalData: (_key: Uint8Array, scope: string, purposes: string[], sealed: Uint8Array[]) =>
    sealed.map((value, i) => {
      const [s, p, body] = new TextDecoder().decode(value).split('|')
      if (s !== scope || p !== purposes[i] || body === undefined) return null
      return Uint8Array.from(atob(body), (c) => c.charCodeAt(0))
    }),
}
const key = new Uint8Array(32)

describe('SealedStorage', () => {
  beforeEach(() => window.localStorage.clear())

  it('keeps values sealed, per account scope and name', () => {
    const storage = new SealedStorage(wasm, key, 'scope-a')
    storage.write('drafts', { 'direct:bob': { text: 'half a thought' } })
    expect(storage.read('drafts')).toEqual({ 'direct:bob': { text: 'half a thought' } })
    expect(window.localStorage.getItem(storage.key('drafts'))).not.toContain('half a thought')
    expect(new SealedStorage(wasm, key, 'scope-b').read('drafts')).toBeUndefined()
    storage.write('drafts', undefined)
    expect(window.localStorage.getItem(storage.key('drafts'))).toBeNull()
  })

  it('takes over a plaintext value once and removes it', () => {
    window.localStorage.setItem('kutup:chat:read:u1', JSON.stringify({ 'direct:bob': 5 }))
    const storage = new SealedStorage(wasm, key, 'scope-a')
    expect(storage.read('read-marks', 'kutup:chat:read:u1')).toEqual({ 'direct:bob': 5 })
    expect(window.localStorage.getItem('kutup:chat:read:u1')).toBeNull()
    expect(storage.read('read-marks')).toEqual({ 'direct:bob': 5 })
  })

  it('reads a value it cannot open as absent', () => {
    const storage = new SealedStorage(wasm, key, 'scope-a')
    window.localStorage.setItem(storage.key('drafts'), 'not sealed at all')
    expect(storage.read('drafts')).toBeUndefined()
  })
})
