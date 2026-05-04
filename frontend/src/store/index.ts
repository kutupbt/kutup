import { configureStore } from '@reduxjs/toolkit'
import { useDispatch, useSelector, TypedUseSelectorHook } from 'react-redux'
import authReducer from './authSlice'

// Session persistence: identity fields + cryptographic keys are stored in
// sessionStorage (tab-scoped — cleared when the browser tab closes, inaccessible
// to other tabs). masterKey/privateKey in sessionStorage has the same XSS
// exposure as holding them in Redux memory; the previous exclusion targeted
// localStorage (cross-session persistence), not sessionStorage.
// accessToken is always null on load and refreshed asynchronously by App.tsx
// using the HTTP-only refresh token cookie.
const loadSession = () => {
  try {
    const raw = sessionStorage.getItem('kutup_session')
    if (raw) {
      const saved = JSON.parse(raw)
      return {
        auth: {
          userId: saved.userId ?? null,
          email: saved.email ?? null,
          username: saved.username ?? null,
          isAdmin: saved.isAdmin ?? false,
          storageQuotaBytes: saved.storageQuotaBytes ?? 0,
          storageUsedBytes: saved.storageUsedBytes ?? 0,
          totpEnabled: saved.totpEnabled ?? false,
          accessToken: null, // always null on load — refreshed by App.tsx
          masterKey: saved.masterKey ?? null,
          privateKey: saved.privateKey ?? null,
          publicKey: saved.publicKey ?? null,
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
    sessionStorage.setItem('kutup_session', JSON.stringify({
      userId: auth.userId,
      email: auth.email,
      username: auth.username,
      isAdmin: auth.isAdmin,
      storageQuotaBytes: auth.storageQuotaBytes,
      storageUsedBytes: auth.storageUsedBytes,
      totpEnabled: auth.totpEnabled,
      masterKey: auth.masterKey,   // number[] — JSON-safe
      privateKey: auth.privateKey,
      publicKey: auth.publicKey,
    }))
  } else {
    sessionStorage.removeItem('kutup_session')
  }
})

export type RootState = ReturnType<typeof store.getState>
export type AppDispatch = typeof store.dispatch
export const useAppDispatch = () => useDispatch<AppDispatch>()
export const useAppSelector: TypedUseSelectorHook<RootState> = useSelector
