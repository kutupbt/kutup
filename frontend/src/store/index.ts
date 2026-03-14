import { configureStore } from '@reduxjs/toolkit'
import { useDispatch, useSelector, TypedUseSelectorHook } from 'react-redux'
import authReducer from './authSlice'

// S2-3 fix: Only restore non-sensitive identity fields from sessionStorage.
// masterKey, privateKey, and accessToken are NEVER persisted — they live in
// Redux state for the current page session only and are gone on page refresh,
// requiring the user to re-authenticate (re-derive keys from password).
const loadSession = () => {
  try {
    const raw = sessionStorage.getItem('depo_session')
    if (raw) {
      const saved = JSON.parse(raw)
      // Explicitly whitelist safe fields — sensitive keys are never saved
      return {
        auth: {
          userId: saved.userId ?? null,
          email: saved.email ?? null,
          username: saved.username ?? null,
          isAdmin: saved.isAdmin ?? false,
          storageQuotaBytes: saved.storageQuotaBytes ?? 0,
          storageUsedBytes: saved.storageUsedBytes ?? 0,
          totpEnabled: saved.totpEnabled ?? false,
          // These are intentionally absent — user must re-login after page refresh
          accessToken: null,
          masterKey: null,
          privateKey: null,
          publicKey: null,
        },
      }
    }
  } catch {}
  return undefined
}

export const store = configureStore({
  reducer: { auth: authReducer },
  preloadedState: loadSession(),
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: { ignoredActions: ['auth/setAuth'] },
    }),
  // S2-5 fix: Redux DevTools only in development — prevents key extraction via
  // DevTools time-travel in production builds.
  devTools: process.env.NODE_ENV !== 'production',
})

store.subscribe(() => {
  const { auth } = store.getState()
  if (auth.userId) {
    // S2-3/S2-4 fix: Persist only non-sensitive identity/quota fields.
    // accessToken, masterKey, and privateKey are intentionally excluded.
    sessionStorage.setItem('depo_session', JSON.stringify({
      userId: auth.userId,
      email: auth.email,
      username: auth.username,
      isAdmin: auth.isAdmin,
      storageQuotaBytes: auth.storageQuotaBytes,
      storageUsedBytes: auth.storageUsedBytes,
      totpEnabled: auth.totpEnabled,
    }))
  } else {
    sessionStorage.removeItem('depo_session')
  }
})

export type RootState = ReturnType<typeof store.getState>
export type AppDispatch = typeof store.dispatch
export const useAppDispatch = () => useDispatch<AppDispatch>()
export const useAppSelector: TypedUseSelectorHook<RootState> = useSelector
