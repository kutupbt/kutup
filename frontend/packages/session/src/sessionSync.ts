// Cross-tab signals within one app origin, via BroadcastChannel: a sign-out
// in one tab signs out every tab, and a presence-colour change shows up in
// every open editor without a round-trip.
//
// Key material never crosses this channel: every tab restores its own keys
// from the origin's encrypted session blob (see ./persist).

const CHANNEL_NAME = 'kutup-session'

type Message =
  | { type: 'logout' }
  | { type: 'color-update'; color: string | null }

let channel: BroadcastChannel | null = null

function getChannel(): BroadcastChannel | null {
  if (typeof BroadcastChannel === 'undefined') return null
  if (!channel) channel = new BroadcastChannel(CHANNEL_NAME)
  return channel
}

/** Tell all other tabs of this origin to clear their session — call this at
 * the start of an explicit logout so every tab signs out together. */
export function broadcastLogout(): void {
  const ch = getChannel()
  if (!ch) return
  try { ch.postMessage({ type: 'logout' } satisfies Message) } catch { /* channel closed; nothing to notify */ }
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
  try { ch.postMessage({ type: 'color-update', color } satisfies Message) } catch { /* channel closed; nothing to notify */ }
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
  // Protocol-relative: '//evil.com', and '/\\evil.com', which browsers
  // normalise to '//evil.com'.
  if (next.startsWith('//') || next.startsWith('/\\')) return null
  // Control characters (tabs, newlines) are stripped by URL parsers and can
  // turn '/\t/evil.com' into '//evil.com'.
  for (let i = 0; i < next.length; i++) {
    const code = next.charCodeAt(i)
    if (code < 0x20 || code === 0x7f) return null
  }
  return next
}
