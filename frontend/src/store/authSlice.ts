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
  // Sensitive — in memory only, Uint8Array serializes as plain object in Redux DevTools
  // but is NEVER written to any storage
  masterKey: number[] | null   // stored as number[] to be Redux-serializable
  privateKey: number[] | null
  publicKey: string | null
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
  masterKey: null,
  privateKey: null,
  publicKey: null,
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
    logout(state) {
      sessionStorage.removeItem('depo_session')
      // Zero out sensitive material before clearing
      if (state.masterKey) state.masterKey.fill(0)
      if (state.privateKey) state.privateKey.fill(0)
      return initialState
    },
  },
})

export const { setAuth, updateAccessToken, updateStorageUsed, updateStorageQuota, updateTotpEnabled, logout } = authSlice.actions

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
