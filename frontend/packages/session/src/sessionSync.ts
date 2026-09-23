// Cross-tab session sync via BroadcastChannel.
// New tabs (e.g. opened via window.open for /file/:cid/:fid) get their own
// per-tab sessionStorage. To avoid forcing a fresh login in the new tab, an
// already-authenticated tab broadcasts its sensitive session payload (master
// key, private key, identity, access token) on the same-origin channel; the
// new tab requests it on boot and hydrates Redux + sessionStorage.
//
// Same-origin only — the master key never leaves the user's browser.

const CHANNEL_NAME = 'kutup-session'

export interface SessionPayload {
  userId: string
  email: string | null
  username: string | null
  accessToken: string | null
  isAdmin: boolean
  storageQuotaBytes: number
  storageUsedBytes: number
  totpEnabled: boolean
  color: string | null
  currentDeviceId: number | null
  publicKey: string | null
  masterKey: number[] | null
  privateKey: number[] | null
}

type Message =
  | { type: 'request-session' }
  | { type: 'session-share'; payload: SessionPayload }
  | { type: 'logout' }
  | { type: 'color-update'; color: string | null }

let channel: BroadcastChannel | null = null

function getChannel(): BroadcastChannel | null {
  if (typeof BroadcastChannel === 'undefined') return null
  if (!channel) channel = new BroadcastChannel(CHANNEL_NAME)
  return channel
}

/** Mount the responder: this tab will reply to any `request-session` with the
 * given snapshot. Returns a cleanup function. */
export function startSessionResponder(getSnapshot: () => SessionPayload | null): () => void {
  const ch = getChannel()
  if (!ch) return () => {}
  function onMsg(ev: MessageEvent<Message>) {
    if (ev.data?.type !== 'request-session') return
    const snap = getSnapshot()
    if (snap && snap.userId) {
      ch!.postMessage({ type: 'session-share', payload: snap } satisfies Message)
    }
  }
  ch.addEventListener('message', onMsg)
  return () => ch.removeEventListener('message', onMsg)
}

/** Broadcast a fresh snapshot — call after `setAuth` and after token refresh. */
export function broadcastSession(snapshot: SessionPayload): void {
  const ch = getChannel()
  if (!ch) return
  try {
    ch.postMessage({ type: 'session-share', payload: snapshot } satisfies Message)
  } catch {
    // postMessage can fail if a key happens to be non-cloneable; ignore.
  }
}

/** Ask any other tab for its session. Resolves with the payload or null on
 * timeout. */
export function requestSession(timeoutMs = 500): Promise<SessionPayload | null> {
  return new Promise((resolve) => {
    const ch = getChannel()
    if (!ch) return resolve(null)

    let done = false
    function onMsg(ev: MessageEvent<Message>) {
      if (done) return
      if (ev.data?.type !== 'session-share') return
      done = true
      ch!.removeEventListener('message', onMsg)
      window.clearTimeout(timer)
      resolve(ev.data.payload)
    }
    ch.addEventListener('message', onMsg)

    const timer = window.setTimeout(() => {
      if (done) return
      done = true
      ch.removeEventListener('message', onMsg)
      resolve(null)
    }, timeoutMs)

    ch.postMessage({ type: 'request-session' } satisfies Message)
  })
}

/** Tell all other tabs of this origin to clear their session — call this at
 * the start of an explicit logout so every tab signs out together. */
export function broadcastLogout(): void {
  const ch = getChannel()
  if (!ch) return
  try { ch.postMessage({ type: 'logout' } satisfies Message) } catch {}
}

/** Mount a listener that fires when another tab signals a logout. */
export function startLogoutListener(onLogout: () => void): () => void {
  const ch = getChannel()
  if (!ch) return () => {}
  function onMsg(ev: MessageEvent<Message>) {
    if (ev.data?.type === 'logout') onLogout()
  }
  ch.addEventListener('message', onMsg)
  return () => ch.removeEventListener('message', onMsg)
}

/** Broadcast a presence-color change so other tabs of the same browser
 *  reflect it without a /user/me round-trip. Cross-USER sync still goes
 *  through the WS peer roster. */
export function broadcastColor(color: string | null): void {
  const ch = getChannel()
  if (!ch) return
  try { ch.postMessage({ type: 'color-update', color } satisfies Message) } catch {}
}

/** Mount a listener that fires when another tab updates its presence color. */
export function startColorListener(onColor: (color: string | null) => void): () => void {
  const ch = getChannel()
  if (!ch) return () => {}
  function onMsg(ev: MessageEvent<Message>) {
    if (ev.data?.type === 'color-update') onColor(ev.data.color)
  }
  ch.addEventListener('message', onMsg)
  return () => ch.removeEventListener('message', onMsg)
}

/** Sanitize a `?next=` query value: must be a same-origin pathname. Returns
 * null for anything else (open-redirect protection). */
export function sanitizeNext(next: string | null | undefined): string | null {
  if (!next) return null
  if (!next.startsWith('/')) return null
  if (next.startsWith('//')) return null   // protocol-relative
  return next
}
