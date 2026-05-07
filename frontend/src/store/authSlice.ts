// masterKey and privateKey are held IN MEMORY ONLY — never persisted to localStorage
// or any store persistence layer. They are cleared on logout or page refresh.
import { createSlice, PayloadAction } from '@reduxjs/toolkit'

interface AuthState {
  userId: string | null
  email: string | null
  username: string | null
  accessToken: string | null
  isAdmin: boolean
  storageQuotaBytes: number
  storageUsedBytes: number
  totpEnabled: boolean
  /** Per-user collab presence color. Hex string '#rrggbb', or null if the
   *  user hasn't picked one — clients fall back to a deterministic palette
   *  pick from userId hash. Synced from /user/me on login + persisted via
   *  PATCH /user/me. */
  color: string | null
  // Sensitive — in memory only, Uint8Array serializes as plain object in Redux DevTools
  // but is NEVER written to any storage
  masterKey: number[] | null   // stored as number[] to be Redux-serializable
  privateKey: number[] | null
  publicKey: string | null
  currentDeviceId: number | null
}

const initialState: AuthState = {
  userId: null,
  email: null,
  username: null,
  accessToken: null,
  isAdmin: false,
  storageQuotaBytes: 0,
  storageUsedBytes: 0,
  totpEnabled: false,
  color: null,
  masterKey: null,
  privateKey: null,
  publicKey: null,
  currentDeviceId: null,
}

const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    setAuth(state, action: PayloadAction<{
      userId: string
      email: string
      username?: string
      accessToken: string
      masterKey: Uint8Array
      privateKey: Uint8Array
      publicKey: string
      isAdmin: boolean
      storageQuotaBytes: number
      storageUsedBytes: number
      totpEnabled?: boolean
      color?: string | null
    }>) {
      const p = action.payload
      state.userId = p.userId
      state.email = p.email
      state.username = p.username ?? null
      state.accessToken = p.accessToken
      state.masterKey = Array.from(p.masterKey)
      state.privateKey = Array.from(p.privateKey)
      state.publicKey = p.publicKey
      state.isAdmin = p.isAdmin
      state.storageQuotaBytes = p.storageQuotaBytes
      state.storageUsedBytes = p.storageUsedBytes
      state.totpEnabled = p.totpEnabled ?? false
      state.color = p.color ?? null
    },
    setColor(state, action: PayloadAction<string | null>) {
      state.color = action.payload
    },
    updateAccessToken(state, action: PayloadAction<string>) {
      state.accessToken = action.payload
    },
    updateStorageUsed(state, action: PayloadAction<number>) {
      state.storageUsedBytes = action.payload
    },
    updateStorageQuota(state, action: PayloadAction<number>) {
      state.storageQuotaBytes = action.payload
    },
    updateTotpEnabled(state, action: PayloadAction<boolean>) {
      state.totpEnabled = action.payload
    },
    setDeviceId(state, action: PayloadAction<number | null>) {
      state.currentDeviceId = action.payload
    },
    logout(state) {
      sessionStorage.removeItem('kutup_session')
      // Returning initialState replaces the slice; we can't also mutate
      // the draft (Immer error 4 — "can't return new state AND modify
      // draft"). The old key arrays are abandoned to GC rather than
      // explicitly zeroed. The threat model already assumes that a
      // hostile attacker on the device wins; secure-erase here was
      // hygiene only.
      void state
      return initialState
    },
  },
})

export const { setAuth, updateAccessToken, updateStorageUsed, updateStorageQuota, updateTotpEnabled, setDeviceId, setColor, logout } = authSlice.actions

// Typed selectors that reconstruct Uint8Array from stored number[]
export const selectMasterKey = (state: { auth: AuthState }): Uint8Array | null =>
  state.auth.masterKey ? new Uint8Array(state.auth.masterKey) : null

export const selectPrivateKey = (state: { auth: AuthState }): Uint8Array | null =>
  state.auth.privateKey ? new Uint8Array(state.auth.privateKey) : null

export const selectAccessToken = (state: { auth: AuthState }) => state.auth.accessToken
export const selectUserId = (state: { auth: AuthState }) => state.auth.userId
export const selectIsAdmin = (state: { auth: AuthState }) => state.auth.isAdmin
export const selectIsLoggedIn = (state: { auth: AuthState }) => state.auth.accessToken !== null

export default authSlice.reducer
