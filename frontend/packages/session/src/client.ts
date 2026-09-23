import axios from 'axios'
import { broadcastLogout } from './sessionSync'
import { resolveApiBase } from './apiBase'
import { clearSession, getAccessToken, setAccessToken } from './store'

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
