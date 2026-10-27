// The newest manifest this app has seen of each account it met, its own
// included (docs/plans/one-device-list.md §8, slices 2 and 3): the rollback
// pins a head must follow. One rule for all of them:
//
// - In memory for the page.
// - When this origin keeps its sign-in, also sealed in localStorage, under a
//   key the master key derives (local-state purpose `ManifestPins`, profile
//   `<client type>:<user id>`): the list names who one edits with, so never
//   plain. It survives a new sign-in on this browser, and a server can't
//   undo it.
// - With no pin for an account, its first head that verifies is trusted on
//   first use.

import { openManifestPins, sealManifestPins, type AccountManifestPin } from '@kutup/crypto/accountManifest'
import { accountKeyOf } from '@kutup/crypto/accountRef'
import { toBase64 } from '@kutup/crypto/base64'
import { getClientType } from './client'
import { readPersisted } from './persistedStore'
import { getSession, type Session } from './store'

/** Where #365's plain own-account pins were kept: read once, then removed. */
const PLAIN_PIN_PREFIX = 'kutup_own_manifest_pin_v1:'

function storageKey(userId: string): string {
  return `kutup-manifest-pins:${userId}`
}

function profile(session: Session): string {
  return `${getClientType()}:${session.userId}`
}

/** This origin keeps the sign-in: its pins are kept too. */
function keeps(session: Session): boolean {
  return readPersisted()?.sessionId === session.sessionId
}

let store: { userId: string; pins: Promise<Map<string, AccountManifestPin>> } | null = null
let writes: Promise<unknown> = Promise.resolve()

function signedIn(): Session {
  const session = getSession()
  if (!session) throw new Error('not signed in')
  return session
}

async function load(session: Session): Promise<Map<string, AccountManifestPin>> {
  const pins = new Map<string, AccountManifestPin>()
  try {
    const sealed = localStorage.getItem(storageKey(session.userId))
    if (sealed) {
      for (const pin of await openManifestPins(sealed, toBase64(session.masterKey), profile(session))) {
        pins.set(accountKeyOf(pin.account), pin)
      }
    }
  } catch {
    // Unreadable (storage blocked, or another key): no pins, first use again.
  }
  try {
    for (let i = localStorage.length - 1; i >= 0; i--) {
      const key = localStorage.key(i)
      if (!key?.startsWith(PLAIN_PIN_PREFIX)) continue
      const pin = JSON.parse(localStorage.getItem(key) ?? 'null') as AccountManifestPin | null
      if (pin && !pins.has(accountKeyOf(pin.account))) pins.set(accountKeyOf(pin.account), pin)
      localStorage.removeItem(key)
    }
  } catch {
    // Storage unavailable.
  }
  return pins
}

function pinsOf(session: Session): Promise<Map<string, AccountManifestPin>> {
  if (!store || store.userId !== session.userId) store = { userId: session.userId, pins: load(session) }
  return store.pins
}

/** The pin this app keeps for `account` (`aci:<uuid>@<server>`), if any. */
export async function manifestPin(account: string): Promise<AccountManifestPin | null> {
  return (await pinsOf(signedIn())).get(account) ?? null
}

/** Keeps `pin` as the newest manifest seen of its account. */
export async function keepManifestPin(pin: AccountManifestPin): Promise<void> {
  const session = signedIn()
  const pins = await pinsOf(session)
  const account = accountKeyOf(pin.account)
  const known = pins.get(account)
  if (known && known.incarnationId === pin.incarnationId && known.sequence === pin.sequence && known.hash === pin.hash) return
  pins.set(account, pin)
  if (!keeps(session)) return
  const list = [...pins.values()]
  writes = writes.then(async () => {
    try {
      localStorage.setItem(storageKey(session.userId), await sealManifestPins(list, toBase64(session.masterKey), profile(session)))
    } catch {
      // Storage unavailable: kept for the page only.
    }
  })
  await writes
}

/** Forgets the page's pins (tests, and an account switch). */
export function resetManifestPinsForTesting(): void {
  store = null
}
