// Boot-time session rehydration for the Tauri shell.
//
// Called once from App.tsx on first mount. The web path always returns
// `'/login'` so the existing flow is unaffected.
//
// Flow:
//   1. !isTauri                                → '/login' (web flow unchanged)
//   2. no serverUrl persisted                  → '/server-select'
//   3. no vault payload                        → '/login'
//   4. vault payload found:
//        a. dispatch setAuth() with the stored secrets + profile
//        b. validate with the backend via a non-intercepted fetch to
//           `${apiBase}/user/me` (bypasses axios' auto-redirect-to-login
//           on 401 so we get to choose the response ourselves)
//        c. 200 → '/drive'
//        d. 401 + cookie-refresh succeeds → re-stash new token → '/drive'
//        e. 401 with no refresh available → clear vault + '/login'
//        f. network error → keep user in restored state, '/drive'
//           (offline mode: cached identity is enough to render the
//           drive shell; the first encrypted-asset fetch will surface
//           the offline state naturally)

import { store } from '../store'
import { setAuth, logout, updateAccessToken } from '../store/authSlice'
import * as sessionVault from './sessionVault'
import { isTauri } from './isTauri'
import { getServerUrl } from './serverConfig'
import { resolveApiBase } from './apiBase'

export type RestoreRoute = '/server-select' | '/login' | '/drive'

export interface RestoreResult {
  route: RestoreRoute
}

export async function restoreSession(): Promise<RestoreResult> {
  if (!isTauri) return { route: '/login' }

  const url = await getServerUrl()
  if (!url) return { route: '/server-select' }

  const payload = await sessionVault.load()
  if (!payload) return { route: '/login' }

  // Hydrate Redux first so any concurrent UI render sees the user as
  // signed-in. store.subscribe will mirror identity fields to sessionStorage.
  store.dispatch(
    setAuth({
      userId: payload.profile.userId,
      email: payload.profile.email,
      username: payload.profile.username ?? undefined,
      accessToken: payload.secrets.accessToken,
      masterKey: payload.secrets.masterKey,
      privateKey: payload.secrets.privateKey,
      publicKey: payload.profile.publicKey,
      isAdmin: payload.profile.isAdmin,
      storageQuotaBytes: payload.profile.storageQuotaBytes,
      storageUsedBytes: payload.profile.storageUsedBytes,
      totpEnabled: payload.profile.totpEnabled,
      color: payload.profile.color,
    }),
  )

  const base = await resolveApiBase()
  try {
    const me = await fetch(`${base}/user/me`, {
      headers: { Authorization: `Bearer ${payload.secrets.accessToken}` },
      credentials: 'include',
    })
    if (me.ok) return { route: '/drive' }

    if (me.status === 401) {
      // Try refresh via the httpOnly cookie that the webview persists.
      const refresh = await fetch(`${base}/auth/refresh`, {
        method: 'POST',
        credentials: 'include',
      })
      if (refresh.ok) {
        const { accessToken } = (await refresh.json()) as {
          accessToken: string
        }
        store.dispatch(updateAccessToken(accessToken))
        // Re-stash with the fresh token so the next launch starts valid.
        try {
          await sessionVault.save({
            profile: payload.profile,
            secrets: { ...payload.secrets, accessToken },
          })
        } catch {
          // Non-fatal: user is signed in for this run.
        }
        return { route: '/drive' }
      }
    }

    // 401 with no refresh, or any other non-200: bad session, drop it.
    await sessionVault.clear()
    store.dispatch(logout())
    return { route: '/login' }
  } catch {
    // Network error / DNS fail / server down. Don't penalize the user —
    // keep them in the restored state so they can read cached metadata
    // offline. The next online API call will naturally re-enter the
    // refresh flow.
    return { route: '/drive' }
  }
}
