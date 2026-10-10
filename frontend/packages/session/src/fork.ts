// Session forking between Kutup's web apps (the Proton pattern; design in
// docs/plans/multi-app-web-rewrite.md).
//
//   drive (no session) ──requestFork──▶ account/authorize?app=drive&state=S
//   account (signed in) ──produceFork──▶ POST /api/auth/forks → selector
//        └─▶ <drive origin>/login#selector=…&sk=<32-byte key>&state=S
//   drive ──consumeFork──▶ POST /api/auth/forks/consume (Origin-bound, once)
//        → opens the SessionFork envelope with `sk`, persists, returns to S's path
//
// The key only ever travels in a URL fragment, which browsers never send to a
// server; the server only ever holds the envelope, for 60 seconds, once.

import { fromBase64, toBase64 } from '@kutup/crypto/base64'
import { LocalStatePurpose, openLocalState, sealLocalState } from '@kutup/crypto/localState'
import { appUrl, type AppId } from './apps'
import api, { getClientType } from './client'
import { decodeKeys, encodeKeys } from './keys'
import { persistKeys } from './persist'
import { activateSession } from './profile'
import { sanitizeNext } from './sessionSync'
import { getSession } from './store'

/** The apps the account app forks for, and their session types. */
export type ForkChild = Extract<AppId, 'drive' | 'chat' | 'maps' | 'photos' | 'office' | 'contacts' | 'mail'>
const CHILD_CLIENT: Record<ForkChild, Exclude<import('./client').WebClientType, 'web-account'>> = {
  drive: 'web-drive',
  chat: 'web-chat',
  maps: 'web-maps',
  photos: 'web-photos',
  office: 'web-office',
  contacts: 'web-contacts',
  mail: 'web-mail',
}

export function isForkChild(value: string | null): value is ForkChild {
  return value === 'drive' || value === 'chat' || value === 'maps' || value === 'photos' || value === 'office' || value === 'contacts' || value === 'mail'
}

const STATE_PREFIX = 'kutup-fork:'
/** The child app's path that consumes forks. */
export const FORK_CONSUME_PATH = '/login'

function randomToken(bytes = 24): string {
  return toBase64(crypto.getRandomValues(new Uint8Array(bytes)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

function base64url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function fromBase64url(value: string): Uint8Array {
  const b64 = value.replace(/-/g, '+').replace(/_/g, '/')
  return fromBase64(b64 + '='.repeat((4 - (b64.length % 4)) % 4))
}

/**
 * In drive/chat, with no session: ask the account app for one. The path the
 * user wanted is remembered under a random `state` in this tab's
 * sessionStorage and restored after the fork. Does not return.
 */
export function requestFork(app: ForkChild, returnTo?: string): void {
  const state = randomToken()
  returnTo ??= window.location.pathname + window.location.search + window.location.hash
  sessionStorage.setItem(STATE_PREFIX + state, returnTo)
  window.location.replace(
    appUrl('account', `/authorize?app=${app}&state=${encodeURIComponent(state)}`),
  )
}

/**
 * In the account app, signed in: hand `child` a session. Returns the URL to
 * navigate to (on the child's configured origin, from the server — never
 * from a request parameter).
 */
export function produceFork(child: ForkChild, state: string): Promise<string> {
  // One fork per request: the authorize page may mount again (sign-in,
  // development's double effects), and each call would mint another.
  const key = `${child}:${state}`
  let pending = producing.get(key)
  if (!pending) {
    pending = mintFork(child, state)
    producing.set(key, pending)
    pending.catch(() => producing.delete(key))
  }
  return pending
}

const producing = new Map<string, Promise<string>>()

async function mintFork(child: ForkChild, state: string): Promise<string> {
  const session = getSession()
  if (!session) throw new Error('produceFork() needs a signed-in account session')
  if (!/^[A-Za-z0-9_-]{1,100}$/.test(state)) throw new Error('invalid fork state')
  const clientType = CHILD_CLIENT[child]
  const key = crypto.getRandomValues(new Uint8Array(32))
  const payload = encodeKeys({
    userId: session.userId,
    masterKey: session.masterKey,
    privateKey: session.privateKey,
    publicKey: session.publicKey,
  })
  try {
    const envelope = await sealLocalState(payload, key, LocalStatePurpose.SessionFork, clientType)
    const { data } = await api.post<{ selector: string; childOrigin: string }>('/auth/forks', {
      childClientType: clientType,
      payload: envelope,
    })
    const fragment = new URLSearchParams({ selector: data.selector, sk: base64url(key), state })
    return `${data.childOrigin}${FORK_CONSUME_PATH}#${fragment.toString()}`
  } finally {
    key.fill(0)
    payload.fill(0)
  }
}

/** Whether this page load carries a fork to consume. */
export function hasForkInLocation(): boolean {
  return (
    window.location.pathname === FORK_CONSUME_PATH &&
    new URLSearchParams(window.location.hash.slice(1)).has('selector')
  )
}

/**
 * Where a fork in this page's address asked to go, without using it up: a
 * fork that cannot be redeemed asks for another one to the same place.
 */
export function pendingForkReturnTo(): string {
  const state = new URLSearchParams(window.location.hash.slice(1)).get('state')
  const saved = state ? sanitizeNext(sessionStorage.getItem(STATE_PREFIX + state)) : null
  return saved && !saved.startsWith(FORK_CONSUME_PATH) ? saved : '/'
}

/**
 * In drive/chat, on `/login#selector=…&sk=…&state=…`: redeem the fork, open
 * the keys, persist them for reloads and activate the session. Returns the
 * path to continue to. The fragment is wiped from the address bar and
 * history before anything else happens.
 */
export async function consumeFork(): Promise<string> {
  const params = new URLSearchParams(window.location.hash.slice(1))
  window.history.replaceState(null, '', window.location.pathname + window.location.search)
  const selector = params.get('selector')
  const sk = params.get('sk')
  const state = params.get('state')
  if (!selector || !sk) throw new Error('the sign-in link is incomplete')

  let returnTo = '/'
  if (state) {
    const saved = sessionStorage.getItem(STATE_PREFIX + state)
    sessionStorage.removeItem(STATE_PREFIX + state)
    returnTo = sanitizeNext(saved) ?? '/'
    if (returnTo.startsWith(FORK_CONSUME_PATH)) returnTo = '/'
  }

  const key = fromBase64url(sk)
  if (key.length !== 32) throw new Error('the sign-in link is malformed')
  try {
    const { data } = await api.post<{
      accessToken: string
      sessionId: string
      userId: string
      payload: string
    }>('/auth/forks/consume', { selector })
    const plaintext = await openLocalState(
      data.payload,
      key,
      LocalStatePurpose.SessionFork,
      getClientType(),
    )
    const keys = decodeKeys(plaintext)
    plaintext.fill(0)
    if (keys.userId !== data.userId) throw new Error('the fork belongs to another account')
    await activateSession(keys, data.accessToken, data.sessionId)
    await persistKeys(data.sessionId, keys)
    return returnTo
  } finally {
    key.fill(0)
  }
}
