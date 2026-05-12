import axios from 'axios'
import { store } from '../store'
import { updateAccessToken, logout } from '../store/authSlice'
import { broadcastLogout } from '../lib/sessionSync'
import { resolveApiBase } from '../lib/apiBase'
import { isTauri } from '../lib/isTauri'
import * as sessionVault from '../lib/sessionVault'

// In the Tauri shell, use axios's fetch adapter so requests go through
// `globalThis.fetch` — which lib/httpClient's installTauriFetch() has swapped
// for tauri-plugin-http. That bypasses the webview CORS layer and lets the
// per-server "skip TLS verification" flag take effect. On the web, the
// default xhr adapter is used and behaviour is unchanged.
if (isTauri) {
  axios.defaults.adapter = 'fetch'
}

// baseURL is resolved per-request via the interceptor below so the Tauri
// shell can talk to a user-selected backend (`tauri://localhost` cannot
// route a bare `/api` to the backend). On the web `resolveApiBase()`
// returns `/api` and behaviour is unchanged.
const api = axios.create({
  withCredentials: true,
})

// Attach access token + resolve base URL on every request.
api.interceptors.request.use(async (config) => {
  config.baseURL = await resolveApiBase()
  const token = store.getState().auth.accessToken
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Auto-refresh on 401
let isRefreshing = false
let failedQueue: Array<{ resolve: (t: string) => void; reject: (e: unknown) => void }> = []

const processQueue = (error: unknown, token: string | null) => {
  failedQueue.forEach(({ resolve, reject }) => {
    if (error) reject(error)
    else resolve(token!)
  })
  failedQueue = []
}

// Sleep helper for retry backoff.
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms))

api.interceptors.response.use(
  (res) => res,
  async (error) => {
    const originalRequest = error.config
    const status = error.response?.status
    // If axios couldn't even attach the request config (some network-layer
    // failures, MSW edge cases, etc.), there's nothing to retry. Bail.
    if (!originalRequest) return Promise.reject(error)

    // Transient failures (503 from rate limiter, 429 from anywhere, or
    // network-level disconnects). Retry up to 3 times with 0.5/1/2 s backoff
    // before bubbling the error to the caller.
    const isTransient =
      status === 503 ||
      status === 429 ||
      (error.code === 'ECONNABORTED') ||
      (error.message === 'Network Error')
    if (originalRequest && isTransient) {
      originalRequest._transientRetries = (originalRequest._transientRetries ?? 0) + 1
      if (originalRequest._transientRetries <= 3) {
        const wait = 500 * Math.pow(2, originalRequest._transientRetries - 1)
        await sleep(wait)
        return api(originalRequest)
      }
    }

    const skipRefresh = originalRequest.url?.match(/\/auth\/(login|register|recover)/)
    if (status === 401 && !originalRequest._retry && !skipRefresh) {
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject })
        }).then((token) => {
          originalRequest.headers.Authorization = `Bearer ${token}`
          return api(originalRequest)
        })
      }

      originalRequest._retry = true
      isRefreshing = true

      try {
        const base = await resolveApiBase()
        const res = await axios.post(`${base}/auth/refresh`, {}, { withCredentials: true })
        const newToken = res.data.accessToken
        store.dispatch(updateAccessToken(newToken))
        processQueue(null, newToken)
        originalRequest.headers.Authorization = `Bearer ${newToken}`
        return api(originalRequest)
      } catch (refreshError) {
        processQueue(refreshError, null)
        // Refresh failed → server-side session is gone. Tell every tab to
        // clear local state too, wipe any Tauri-side keyring vault (so
        // the next launch doesn't auto-rehydrate into a dead session),
        // then redirect this tab to /login.
        broadcastLogout()
        try { await sessionVault.clear() } catch { /* best-effort */ }
        store.dispatch(logout())
        window.location.href = '/login'
        return Promise.reject(refreshError)
      } finally {
        isRefreshing = false
      }
    }
    return Promise.reject(error)
  },
)

export default api
