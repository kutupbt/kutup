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

/** The pins this origin keeps sealed for the account, or none. */
async function readSealed(session: Session): Promise<AccountManifestPin[]> {
  try {
    const sealed = localStorage.getItem(storageKey(session.userId))
    if (!sealed) return []
    return await openManifestPins(sealed, toBase64(session.masterKey), profile(session))
  } catch {
    // Unreadable (storage blocked, or another key): none, first use again.
    return []
  }
}

/**
 * Whether `pin` goes in over `known`: a pin only moves forward within its
 * incarnation (another tab, or a late answer, can't take it back); another
 * incarnation is a reset this tab verified, and replaces it.
 */
function supersedes(pin: AccountManifestPin, known: AccountManifestPin | undefined): boolean {
  if (!known || known.incarnationId !== pin.incarnationId) return true
  return pin.sequence > known.sequence
}

function merge(into: Map<string, AccountManifestPin>, pins: Iterable<AccountManifestPin>): void {
  for (const pin of pins) {
    const account = accountKeyOf(pin.account)
    const known = into.get(account)
    // Another incarnation from elsewhere doesn't override this tab's.
    if (known && known.incarnationId !== pin.incarnationId) continue
    if (supersedes(pin, known)) into.set(account, pin)
  }
}

/** Writes the page's pins, merged with what other tabs kept since, sealed. */
async function persist(session: Session, pins: Map<string, AccountManifestPin>, forget?: string): Promise<void> {
  if (!keeps(session)) return
  writes = writes.then(async () => {
    try {
      const merged = new Map(pins)
      merge(merged, await readSealed(session))
      if (forget) merged.delete(forget)
      for (const [account, pin] of merged) pins.set(account, pin)
      localStorage.setItem(
        storageKey(session.userId),
        await sealManifestPins([...merged.values()], toBase64(session.masterKey), profile(session)),
      )
    } catch {
      // Storage unavailable: kept for the page only.
    }
  })
  await writes
}

async function load(session: Session): Promise<Map<string, AccountManifestPin>> {
  const pins = new Map<string, AccountManifestPin>()
  merge(pins, await readSealed(session))
  // #365's plain own-account pins: taken in, sealed, and only then removed.
  const plain: string[] = []
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i)
      if (!key?.startsWith(PLAIN_PIN_PREFIX)) continue
      plain.push(key)
      try {
        const pin = JSON.parse(localStorage.getItem(key) ?? 'null') as AccountManifestPin | null
        if (pin) merge(pins, [pin])
      } catch {
        // One unreadable entry: the others still count.
      }
    }
  } catch {
    // Storage unavailable.
  }
  if (plain.length > 0) {
    await persist(session, pins)
    try {
      for (const key of plain) localStorage.removeItem(key)
    } catch {
      // Storage unavailable.
    }
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

/** Keeps `pin` as the newest manifest seen of its account (never an older one of its incarnation). */
export async function keepManifestPin(pin: AccountManifestPin): Promise<void> {
  const session = signedIn()
  const pins = await pinsOf(session)
  const account = accountKeyOf(pin.account)
  if (!supersedes(pin, pins.get(account))) return
  pins.set(account, pin)
  await persist(session, pins)
}

/**
 * Forgets `account`'s pin: its next head is trusted on first use again. For
 * a reset the user chose to trust (`SenderRefusal.trust`).
 */
export async function forgetManifestPin(account: string): Promise<void> {
  const session = signedIn()
  const pins = await pinsOf(session)
  pins.delete(account)
  await persist(session, pins, account)
}

/** Forgets the page's pins (tests, and an account switch). */
export function resetManifestPinsForTesting(): void {
  store = null
}
