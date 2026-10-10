import { beforeEach, describe, expect, it, vi } from 'vitest'

const post = vi.fn()
vi.mock('./client', () => ({
  default: { post: (...args: unknown[]) => post(...args) },
  getClientType: () => 'web-drive',
}))
vi.mock('./apps', () => ({
  appUrl: (app: string, path: string) => `https://${app}.example.org${path}`,
}))
const activateSession = vi.fn()
vi.mock('./profile', () => ({ activateSession: (...a: unknown[]) => activateSession(...a) }))
const persistKeys = vi.fn()
vi.mock('./persist', () => ({ persistKeys: (...a: unknown[]) => persistKeys(...a) }))
const opened: { value: Uint8Array } = { value: new Uint8Array() }
vi.mock('@kutup/crypto/localState', () => ({
  LocalStatePurpose: { SessionFork: 2, WebSession: 3 },
  sealLocalState: vi.fn(async () => 'ENVELOPE'),
  openLocalState: vi.fn(async () => opened.value),
}))

import { encodeKeys, decodeKeys } from './keys'
import { consumeFork, hasForkInLocation, produceFork, requestFork, UnrequestedForkError } from './fork'
import { clearSession, setSession } from './store'

const keys = {
  userId: 'u1',
  masterKey: new Uint8Array(32).fill(1),
  privateKey: new Uint8Array(32).fill(2),
  publicKey: 'cHVi',
}
const sk = 'A'.repeat(43) // base64url of 32 zero bytes

function visit(url: string) {
  window.history.replaceState(null, '', url)
}

beforeEach(() => {
  post.mockReset()
  activateSession.mockReset()
  persistKeys.mockReset()
  sessionStorage.clear()
  clearSession()
  opened.value = encodeKeys(keys)
})

describe('keys', () => {
  it('round-trip and reject malformed payloads', () => {
    expect(decodeKeys(encodeKeys(keys))).toEqual(keys)
    expect(() => decodeKeys(new TextEncoder().encode('{"v":2}'))).toThrow()
    const short = encodeKeys({ ...keys, masterKey: new Uint8Array(16) })
    expect(() => decodeKeys(short)).toThrow(/wrong length/)
  })
})

describe('requestFork', () => {
  it('remembers where the user was and goes to the account app', () => {
    const replace = vi.fn()
    const original = window.location
    visit('/folders/abc?sort=name')
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { ...original, pathname: '/folders/abc', search: '?sort=name', hash: '', replace },
    })
    try {
      requestFork('drive')
    } finally {
      Object.defineProperty(window, 'location', { configurable: true, value: original })
    }
    const target = new URL(replace.mock.calls[0]![0] as string)
    expect(target.origin).toBe('https://account.example.org')
    expect(target.pathname).toBe('/authorize')
    expect(target.searchParams.get('app')).toBe('drive')
    const state = target.searchParams.get('state')!
    expect(sessionStorage.getItem(`kutup-fork:${state}`)).toBe('/folders/abc?sort=name')
  })
})

describe('produceFork', () => {
  it('sends the child to the origin the server names, key only in the fragment', async () => {
    setSession({ sessionId: 's', ...keys, email: 'a@b.c', username: null, isAdmin: false,
      storageQuotaBytes: 0, storageUsedBytes: 0, totpEnabled: false, color: null,
      currentDeviceId: null }, 'token')
    post.mockResolvedValue({ data: { selector: 'SEL', childOrigin: 'https://drive.example.org' } })
    const url = new URL(await produceFork('drive', 'st_1'))
    expect(post).toHaveBeenCalledWith('/auth/forks', { childClientType: 'web-drive', payload: 'ENVELOPE' })
    expect(url.origin).toBe('https://drive.example.org')
    expect(url.pathname).toBe('/login')
    expect(url.search).toBe('')
    const fragment = new URLSearchParams(url.hash.slice(1))
    expect(fragment.get('selector')).toBe('SEL')
    expect(fragment.get('sk')).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(fragment.get('state')).toBe('st_1')
  })

  it('refuses a malformed state', async () => {
    setSession({ sessionId: 's', ...keys, email: 'a@b.c', username: null, isAdmin: false,
      storageQuotaBytes: 0, storageUsedBytes: 0, totpEnabled: false, color: null,
      currentDeviceId: null }, 'token')
    await expect(produceFork('drive', 'bad state/..')).rejects.toThrow(/state/)
  })
})

describe('consumeFork', () => {
  beforeEach(() => {
    post.mockResolvedValue({
      data: { accessToken: 'AT', sessionId: 'S2', userId: 'u1', payload: 'ENV' },
    })
  })

  it('wipes the fragment, redeems once, persists, and returns to the saved path', async () => {
    sessionStorage.setItem('kutup-fork:st', '/folders/abc')
    visit(`/login#selector=SEL&sk=${sk}&state=st`)
    expect(hasForkInLocation()).toBe(true)
    const next = await consumeFork()
    expect(window.location.hash).toBe('')
    expect(post).toHaveBeenCalledWith('/auth/forks/consume', { selector: 'SEL' })
    expect(activateSession).toHaveBeenCalledWith(expect.objectContaining({ userId: 'u1' }), 'AT', 'S2')
    expect(persistKeys).toHaveBeenCalledWith('S2', expect.objectContaining({ userId: 'u1' }))
    expect(next).toBe('/folders/abc')
    expect(sessionStorage.getItem('kutup-fork:st')).toBeNull()
  })

  it('never returns to another origin', async () => {
    sessionStorage.setItem('kutup-fork:st', '//evil.example/phish')
    visit(`/login#selector=SEL&sk=${sk}&state=st`)
    expect(await consumeFork()).toBe('/')
  })

  it('refuses keys for another account', async () => {
    opened.value = encodeKeys({ ...keys, userId: 'someone-else' })
    sessionStorage.setItem('kutup-fork:st', '/')
    visit(`/login#selector=SEL&sk=${sk}&state=st`)
    await expect(consumeFork()).rejects.toThrow(/another account/)
    expect(activateSession).not.toHaveBeenCalled()
  })

  it('never redeems a link this tab did not ask for', async () => {
    // Someone else's fork, sent to this browser (login CSRF): no state, or
    // one this tab never saved.
    for (const fragment of [`selector=SEL&sk=${sk}`, `selector=SEL&sk=${sk}&state=theirs`]) {
      visit(`/login#${fragment}`)
      await expect(consumeFork()).rejects.toBeInstanceOf(UnrequestedForkError)
      expect(window.location.hash).toBe('')
    }
    expect(post).not.toHaveBeenCalled()
    expect(activateSession).not.toHaveBeenCalled()
  })

  it('redeems a state once: the same link twice is refused', async () => {
    sessionStorage.setItem('kutup-fork:st', '/folders/abc')
    visit(`/login#selector=SEL&sk=${sk}&state=st`)
    await consumeFork()
    visit(`/login#selector=SEL&sk=${sk}&state=st`)
    await expect(consumeFork()).rejects.toBeInstanceOf(UnrequestedForkError)
    expect(post).toHaveBeenCalledTimes(1)
  })

  it('refuses an incomplete link without calling the server', async () => {
    visit('/login#selector=SEL')
    await expect(consumeFork()).rejects.toThrow(/incomplete/)
    expect(post).not.toHaveBeenCalled()
    expect(window.location.hash).toBe('')
  })
})
