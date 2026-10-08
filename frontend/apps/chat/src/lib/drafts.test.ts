import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { SealedStorage } from '@kutup/chat-core/sealedStorage'
import { setSealedStorage } from '../state/sealedState'
import { clearDrafts, getDraft, setDraft } from './drafts'

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

describe('drafts', () => {
  let storage: SealedStorage
  beforeEach(() => {
    window.localStorage.clear()
    storage = new SealedStorage(wasm, new Uint8Array(32), 'scope-a')
    setSealedStorage(storage)
  })
  afterEach(() => setSealedStorage(null))

  it('keeps a draft per conversation, sealed, until it is emptied', () => {
    setDraft('direct:bob@a.test', { text: 'half a thought', picks: [] })
    expect(getDraft('direct:bob@a.test')?.text).toBe('half a thought')
    expect(window.localStorage.getItem(storage.key('drafts'))).not.toContain('half a thought')
    setDraft('direct:bob@a.test', { text: '   ', picks: [] })
    expect(getDraft('direct:bob@a.test')).toBeUndefined()
  })

  it('belongs to the open account only, and goes on sign-out', () => {
    setDraft('group:g1', { text: 'plan', picks: [] })
    setSealedStorage(new SealedStorage(wasm, new Uint8Array(32), 'scope-b'))
    expect(getDraft('group:g1')).toBeUndefined()
    setSealedStorage(storage)
    expect(getDraft('group:g1')?.text).toBe('plan')
    clearDrafts()
    expect(getDraft('group:g1')).toBeUndefined()
    expect(window.localStorage.getItem(storage.key('drafts'))).toBeNull()
  })

  it('keeps nothing while no account is open', () => {
    setSealedStorage(null)
    setDraft('direct:bob@a.test', { text: 'lost', picks: [] })
    setSealedStorage(storage)
    expect(getDraft('direct:bob@a.test')).toBeUndefined()
  })
})
