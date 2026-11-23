import axios, { type InternalAxiosRequestConfig } from 'axios'
import { exactBytes } from '@kutup/crypto/bytes'
import { broadcastLogout } from './sessionSync'
import { resolveApiBase } from './apiBase'
import { clearPersisted } from './persistedStore'
import { clearSession, getAccessToken, setAccessToken } from './store'
import { noteSessionVersion, SESSION_VERSION_HEADER } from './sessionVersion'
import { CLIENT_HEADER, ClientTooOldError, clientVersionValue, isClientTooOld, isTooOldAnswer, latchClientTooOld, setClientType } from './clientVersion'
import { ensureInstance, INSTANCE_HEADER, noteInstance } from './instance'
import { startInstanceListener } from './sessionSync'
import { setStorageGate } from '@kutup/crypto/storageGate'

/** The server-side session types a web app can hold (X-Kutup-Client). */
export type WebClientType = 'web-account' | 'web-drive' | 'web-chat' | 'web-maps' | 'web-photos' | 'web-office' | 'web-contacts' | 'web-mail' | 'web-pass' | 'web-calendar'

let clientType: WebClientType | null = null

/**
 * Called once at boot: every request (and the raw refresh call) tells the
 * server which app it is, which decides the session type and that refresh
 * tokens travel in this origin's HttpOnly cookie.
 */
export function configureClient(opts: { clientType: WebClientType }): void {
  clientType = opts.clientType
  setClientType(opts.clientType)
  api.defaults.headers.common[CLIENT_HEADER] = clientVersionValue()
  // Nothing reads this origin's storage before the instance check
  // (docs/plans/api-surface.md §5); another tab's reset reloads this one.
  setStorageGate(ensureInstance)
  if (typeof window !== 'undefined') startInstanceListener(() => window.location.reload())
}

export function getClientType(): WebClientType {
  if (!clientType) throw new Error('configureClient() has not run')
  return clientType
}

export { ClientTooOldError, isClientTooOld, resetClientTooOld } from './clientVersion'

/**
 * Latches a `clientTooOld` answer (docs/plans/api-surface.md §1.5): every
 * later request fails at once, and the page offers its reload, as Proton
 * latches APP_VERSION_BAD. Returns whether `error` was one.
 */
export function noteClientTooOld(error: unknown): boolean {
  const response = (error as { response?: { status?: number; data?: { code?: unknown } } } | null)?.response
  if (!isTooOldAnswer(response?.status, response?.data?.code)) return false
  latchClientTooOld()
  return true
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
    if (isClientTooOld()) throw new ClientTooOldError()
    const base = await resolveApiBase()
    try {
      const res = await axios.post<RefreshResult>(
        `${base}/auth/refresh`,
        {},
        { withCredentials: true, headers: { [CLIENT_HEADER]: clientVersionValue() ?? getClientType() } },
      )
      return res.data
    } catch (error) {
      if (noteClientTooOld(error)) throw new ClientTooOldError()
      throw error
    }
  }
  if (typeof navigator !== 'undefined' && navigator.locks) {
    return navigator.locks.request('kutup.session.refresh', run)
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

/**
 * The server-side session is gone (a refresh failed): every tab of this
 * origin clears its local state, then the app decides where to go (login or
 * a new fork).
 */
export function endSession(): void {
  broadcastLogout()
  clearPersisted()
  clearSession()
  onUnauthenticated()
}

/** A new access token for this session, or the session ends (and this throws). */
export async function refreshOrEnd(): Promise<string> {
  try {
    const { accessToken } = await refreshAccessToken()
    setAccessToken(accessToken)
    return accessToken
  } catch (error) {
    endSession()
    throw error
  }
}

const api = axios.create({
  withCredentials: true,
})

/**
 * A typed-array or DataView body goes as exactly its own bytes. Left to
 * itself axios sends a view's whole backing buffer, which for a view that
 * WASM handed back is the module's whole memory (`@kutup/crypto/bytes`).
 * On this client and on the default instance (anonymous and raw calls).
 */
export function exactBody<T extends Pick<InternalAxiosRequestConfig, 'data'>>(config: T): T {
  if (ArrayBuffer.isView(config.data)) config.data = exactBytes(config.data)
  return config
}

api.interceptors.request.use(exactBody)
axios.interceptors.request.use(exactBody)

// Attach access token + resolve base URL on every request.
api.interceptors.request.use(async (config) => {
  if (isClientTooOld()) throw new ClientTooOldError()
  config.baseURL = await resolveApiBase()
  const token = getAccessToken()
  // A request that names its own credential (an administrator-made account's
  // setup token) keeps it.
  if (token && !config.headers.Authorization) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

/**
 * The sign-in calls, matched on the whole path (with or without the `/api`
 * base): their 401 never means this session's token ran out. The fork
 * consume is here because it carries no token at all (its link and the
 * Origin are its credential).
 */
const SIGN_IN_CALL =
  /(?:^|\/api\/v1)\/auth\/(?:login\/(?:start|finish|2fa)|register|opaque\/register\/(?:start|finish)|complete-setup|recover\/(?:preflight|grant)|refresh|logout|registration-code\/check|settings|forks\/consume)$/

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
  (res) => {
    noteSessionVersion(res.headers?.[SESSION_VERSION_HEADER])
    noteInstance(res.headers?.[INSTANCE_HEADER])
    return res
  },
  async (error) => {
    noteSessionVersion(error.response?.headers?.[SESSION_VERSION_HEADER])
    if (noteClientTooOld(error)) return Promise.reject(new ClientTooOldError())
    const originalRequest = error.config
    const status = error.response?.status
    // If axios couldn't even attach the request config (some network-layer
    // failures, MSW edge cases, etc.), there's nothing to retry. Bail.
    if (!originalRequest) return Promise.reject(error)

    // Transient failures (503 from rate limiter, 429 from anywhere, or
    // network-level disconnects). Retry up to 3 times with 0.5/1/2 s backoff
    // before bubbling the error to the caller.
    // The account's lockout is not transient: asking again only waits it out.
    // Nor is a public link's password lockout (docs/plans/drive-link-password.md):
    // its page says when to try again (`Retry-After`).
    const lockedOut =
      status === 429 && (error.response?.data?.code === 'accountLocked' || error.response?.data?.code === 'linkPasswordLocked')
    const isTransient =
      status === 503 ||
      (status === 429 && !lockedOut) ||
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

    // A 401 from a sign-in call is about its own credential (a password, a
    // pre-auth or setup token, a fork link), not this session's token:
    // refreshing would end this origin's other tabs when there is no
    // session, or retry with another account's token when there is one.
    // Signed-in password checks restart themselves (reauth.ts). Every other
    // call, /api/v1/auth/sessions and /api/v1/auth/forks included, refreshes.
    const code = (error.response?.data as { code?: unknown } | undefined)?.code
    const skipRefresh =
      SIGN_IN_CALL.test((originalRequest.url ?? '').split('?')[0]!) ||
      code === 'invalidCredentials' ||
      code === 'setupTokenInvalid' ||
      code === 'preAuthInvalid' ||
      // A Chat device's own credential (X-Kutup-Device) refused: the
      // device was removed, not this session.
      code === 'deviceCredential' ||
      // A public link's password missing or wrong: the link's, not the session's.
      code === 'linkPassword' ||
      code === 'linkPasswordWrong'
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
        endSession()
        return Promise.reject(refreshError)
      } finally {
        isRefreshing = false
      }
    }
    return Promise.reject(error)
  },
)

export default api
