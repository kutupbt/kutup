import axios from 'axios'
import { store } from '../store'
import { updateAccessToken, logout } from '../store/authSlice'
import { broadcastLogout } from '../lib/sessionSync'

const api = axios.create({
  baseURL: '/api',
  withCredentials: true,
})

// Attach access token to every request
api.interceptors.request.use((config) => {
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
        const res = await axios.post('/api/auth/refresh', {}, { withCredentials: true })
        const newToken = res.data.accessToken
        store.dispatch(updateAccessToken(newToken))
        processQueue(null, newToken)
        originalRequest.headers.Authorization = `Bearer ${newToken}`
        return api(originalRequest)
      } catch (refreshError) {
        processQueue(refreshError, null)
        // Refresh failed → server-side session is gone. Tell every tab to
        // clear local state too, then redirect this tab to /login.
        broadcastLogout()
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
