import { describe, it, expect, beforeEach, beforeAll } from 'vitest'

// authSlice's logout reducer touches sessionStorage. Vitest's default
// 'node' environment doesn't have it, so stub a minimal in-memory shim.
beforeAll(() => {
  if (typeof globalThis.sessionStorage === 'undefined') {
    const store = new Map<string, string>()
    ;(globalThis as { sessionStorage: Storage }).sessionStorage = {
      getItem: (k) => (store.has(k) ? store.get(k)! : null),
      setItem: (k, v) => void store.set(k, v),
      removeItem: (k) => void store.delete(k),
      clear: () => void store.clear(),
      key: (i) => Array.from(store.keys())[i] ?? null,
      get length() { return store.size },
    }
  }
})


import authReducer, {
  setAuth,
  updateAccessToken,
  updateStorageUsed,
  updateStorageQuota,
  updateTotpEnabled,
  setDeviceId,
  logout,
  selectAccessToken,
  selectMasterKey,
  selectPrivateKey,
  selectIsLoggedIn,
  selectIsAdmin,
  selectUserId,
} from './authSlice'

const validAuthPayload = {
  userId: 'user-123',
  email: 'a@b.c',
  username: 'alice',
  accessToken: 'jwt-token',
  masterKey: new Uint8Array([1, 2, 3, 4]),
  privateKey: new Uint8Array([5, 6, 7, 8]),
  publicKey: 'pubkey-base64',
  isAdmin: true,
  storageQuotaBytes: 1024,
  storageUsedBytes: 512,
  totpEnabled: true,
}

const initialState = authReducer(undefined, { type: '@@INIT' })

describe('authSlice — initial state', () => {
  it('starts logged out with all sensitive fields null', () => {
    expect(initialState.userId).toBeNull()
    expect(initialState.accessToken).toBeNull()
    expect(initialState.masterKey).toBeNull()
    expect(initialState.privateKey).toBeNull()
    expect(initialState.isAdmin).toBe(false)
  })
})

describe('authSlice — setAuth', () => {
  it('populates every field from payload', () => {
    const state = authReducer(initialState, setAuth(validAuthPayload))
    expect(state.userId).toBe('user-123')
    expect(state.email).toBe('a@b.c')
    expect(state.username).toBe('alice')
    expect(state.accessToken).toBe('jwt-token')
    expect(state.publicKey).toBe('pubkey-base64')
    expect(state.isAdmin).toBe(true)
    expect(state.storageQuotaBytes).toBe(1024)
    expect(state.storageUsedBytes).toBe(512)
    expect(state.totpEnabled).toBe(true)
  })

  it('stores keys as JSON-safe number[]', () => {
    const state = authReducer(initialState, setAuth(validAuthPayload))
    expect(state.masterKey).toEqual([1, 2, 3, 4])
    expect(state.privateKey).toEqual([5, 6, 7, 8])
    // Reducer must NOT leave a Uint8Array on state — Redux DevTools / persistence
    // serialise number[] cleanly but Uint8Array becomes a sparse object.
    expect(Array.isArray(state.masterKey)).toBe(true)
  })

  it('defaults username to null when omitted', () => {
    const { username, ...rest } = validAuthPayload
    void username
    const state = authReducer(initialState, setAuth(rest as any))
    expect(state.username).toBeNull()
  })

  it('defaults totpEnabled to false when omitted', () => {
    const { totpEnabled, ...rest } = validAuthPayload
    void totpEnabled
    const state = authReducer(initialState, setAuth(rest as any))
    expect(state.totpEnabled).toBe(false)
  })
})

describe('authSlice — patch reducers', () => {
  let logged: ReturnType<typeof authReducer>
  beforeEach(() => {
    logged = authReducer(initialState, setAuth(validAuthPayload))
  })

  it('updateAccessToken replaces only the token', () => {
    const next = authReducer(logged, updateAccessToken('new-jwt'))
    expect(next.accessToken).toBe('new-jwt')
    expect(next.userId).toBe(logged.userId)
    expect(next.masterKey).toBe(logged.masterKey)
  })

  it('updateStorageUsed / updateStorageQuota touch only the targeted field', () => {
    let next = authReducer(logged, updateStorageUsed(9999))
    expect(next.storageUsedBytes).toBe(9999)
    expect(next.storageQuotaBytes).toBe(logged.storageQuotaBytes)
    next = authReducer(next, updateStorageQuota(123_000))
    expect(next.storageQuotaBytes).toBe(123_000)
  })

  it('updateTotpEnabled toggles the field', () => {
    const off = authReducer(logged, updateTotpEnabled(false))
    expect(off.totpEnabled).toBe(false)
    const on = authReducer(off, updateTotpEnabled(true))
    expect(on.totpEnabled).toBe(true)
  })

  it('setDeviceId updates currentDeviceId (number or null)', () => {
    const set = authReducer(logged, setDeviceId(42))
    expect(set.currentDeviceId).toBe(42)
    const cleared = authReducer(set, setDeviceId(null))
    expect(cleared.currentDeviceId).toBeNull()
  })
})

describe('authSlice — logout', () => {
  it('returns the slice to its initial state (clears all fields)', () => {
    const logged = authReducer(initialState, setAuth(validAuthPayload))
    expect(logged.userId).not.toBeNull() // sanity
    const out = authReducer(logged, logout())
    expect(out).toEqual(initialState)
    expect(out.masterKey).toBeNull()
    expect(out.privateKey).toBeNull()
    expect(out.accessToken).toBeNull()
  })
})

describe('authSlice — selectors', () => {
  const state = { auth: authReducer(initialState, setAuth(validAuthPayload)) }

  it('selectAccessToken / selectUserId / selectIsAdmin', () => {
    expect(selectAccessToken(state)).toBe('jwt-token')
    expect(selectUserId(state)).toBe('user-123')
    expect(selectIsAdmin(state)).toBe(true)
  })

  it('selectIsLoggedIn is true when accessToken set', () => {
    expect(selectIsLoggedIn(state)).toBe(true)
    const out = { auth: authReducer(state.auth, logout()) }
    expect(selectIsLoggedIn(out)).toBe(false)
  })

  it('selectMasterKey reconstructs Uint8Array from stored number[]', () => {
    const k = selectMasterKey(state)
    expect(k).toBeInstanceOf(Uint8Array)
    expect(Array.from(k!)).toEqual([1, 2, 3, 4])
  })

  it('selectMasterKey returns null when not authenticated', () => {
    const empty = { auth: initialState }
    expect(selectMasterKey(empty)).toBeNull()
    expect(selectPrivateKey(empty)).toBeNull()
  })
})
