import axios from 'axios'
import { broadcastLogout } from './sessionSync'
import { resolveApiBase } from './apiBase'
import { clearPersisted } from './persistedStore'
import { clearSession, getAccessToken, setAccessToken } from './store'

/** The server-side session types a web app can hold (X-Kutup-Client). */
export type WebClientType = 'web-account' | 'web-drive' | 'web-chat' | 'web-maps'

let clientType: WebClientType | null = null

/**
 * Called once at boot: every request (and the raw refresh call) tells the
 * server which app it is, which decides the session type and that refresh
 * tokens travel in this origin's HttpOnly cookie.
 */
export function configureClient(opts: { clientType: WebClientType }): void {
  clientType = opts.clientType
  api.defaults.headers.common['X-Kutup-Client'] = opts.clientType
}

export function getClientType(): WebClientType {
  if (!clientType) throw new Error('configureClient() has not run')
  return clientType
}

export interface RefreshResult {
  accessToken: string
  sessionId: string
}

/**
 * Rotate this origin's refresh cookie for a new access token. Serialised
 * across tabs with a Web Lock: tabs share the cookie, and a second tab
 * refreshing with a token the first just rotated would only hit the server's
 * grace window.
 */
export async function refreshAccessToken(): Promise<RefreshResult> {
  const run = async (): Promise<RefreshResult> => {
    const base = await resolveApiBase()
    const res = await axios.post<RefreshResult>(
      `${base}/auth/refresh`,
      {},
      { withCredentials: true, headers: { 'X-Kutup-Client': getClientType() } },
    )
    return res.data
  }
  if (typeof navigator !== 'undefined' && navigator.locks) {
    return navigator.locks.request('kutup-refresh', run)
  }
  return run()
}

/** Seconds until a JWT's `exp`; -1 when unreadable. */
function secondsLeft(token: string): number {
  try {
    const payload = JSON.parse(atob(token.split('.')[1]!.replace(/-/g, '+').replace(/_/g, '/'))) as { exp?: number }
    return typeof payload.exp === 'number' ? payload.exp - Date.now() / 1000 : -1
  } catch {
    return -1
  }
}

/**
 * The access token for a long-running request (an upload, a download, a
 * WebSocket): the current one, or a freshly rotated one when it has less than
 * a minute left. Axios requests refresh on 401 by themselves; these do not.
 */
export async function freshAccessToken(): Promise<string> {
  const token = getAccessToken()
  if (token && secondsLeft(token) > 60) return token
  const { accessToken } = await refreshAccessToken()
  setAccessToken(accessToken)
  return accessToken
}

// What the app does when the server-side session is gone (refresh failed).
// account. shows its login page; drive. and chat. request a new session fork
// from account. Registered once at app boot.
let onUnauthenticated: () => void = () => {}

export function setUnauthenticatedHandler(handler: () => void): void {
  onUnauthenticated = handler
}

const api = axios.create({
  withCredentials: true,
})

// Attach access token + resolve base URL on every request.
api.interceptors.request.use(async (config) => {
  config.baseURL = await resolveApiBase()
  const token = getAccessToken()
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

    // A 401 from these means "wrong credentials / invalid fork", not an expired
    // access token.
    const skipRefresh = originalRequest.url?.match(
      /\/auth\/(login|register|recover|complete-setup|refresh|forks\/consume)/,
    )
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
        const { accessToken: newToken } = await refreshAccessToken()
        setAccessToken(newToken)
        processQueue(null, newToken)
        originalRequest.headers.Authorization = `Bearer ${newToken}`
        return api(originalRequest)
      } catch (refreshError) {
        processQueue(refreshError, null)
        // Refresh failed → the server-side session is gone. Tell every tab of
        // this origin to clear local state, then let the app decide where to
        // go (login or a new fork).
        broadcastLogout()
        clearPersisted()
        clearSession()
        onUnauthenticated()
        return Promise.reject(refreshError)
      } finally {
        isRefreshing = false
      }
    }
    return Promise.reject(error)
  },
)

export default api
