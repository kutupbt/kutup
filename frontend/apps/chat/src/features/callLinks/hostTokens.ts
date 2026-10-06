// The host tokens of an account's meetings, for the meeting page.
//
// A meeting opens at `/call`, outside the app's sign-in, so that page has no
// session to derive anything from. The signed-in app, which can derive each
// meeting's host token from the account key, leaves them here for it: in
// this browser's storage, on this origin only, under the account they
// belong to. The meeting page uses an account's tokens only after the server
// has confirmed that this browser's sign-in for that account is still live
// (`verifiedHostAccount`), and signing out removes them. So someone else
// who opens the owner's link in this browser later, signed in as another
// account or not at all, is not taken for the owner. Someone who opens their
// own meeting in a browser where they are not signed in is a guest like any
// other, and waits.

import { refreshAccessToken } from '@kutup/session/client'
import { readPersisted } from '@kutup/session/persistedStore'

const KEY = 'kutup-meeting-hosts'
/** As many as an account can have meetings. */
const LIMIT = 50
const ROOM = /^[0-9a-f]{32}$/

type Stored = { v: 2; accounts: Record<string, Record<string, string>> }

function read(): Stored {
  try {
    const parsed = JSON.parse(localStorage.getItem(KEY) ?? 'null') as Partial<Stored> | null
    // Anything else (an older map not tied to an account) is dropped.
    if (!parsed || parsed.v !== 2 || !parsed.accounts || typeof parsed.accounts !== 'object') return { v: 2, accounts: {} }
    const accounts: Stored['accounts'] = {}
    for (const [account, tokens] of Object.entries(parsed.accounts)) {
      if (!tokens || typeof tokens !== 'object' || Array.isArray(tokens)) continue
      accounts[account] = Object.fromEntries(
        Object.entries(tokens as Record<string, unknown>).filter(
          (entry): entry is [string, string] => ROOM.test(entry[0]) && typeof entry[1] === 'string',
        ),
      )
    }
    return { v: 2, accounts }
  } catch {
    return { v: 2, accounts: {} }
  }
}

function write(stored: Stored): void {
  try {
    const accounts = Object.fromEntries(
      Object.entries(stored.accounts)
        .filter(([, tokens]) => Object.keys(tokens).length > 0)
        .map(([account, tokens]) => [account, Object.fromEntries(Object.entries(tokens).slice(-LIMIT))]),
    )
    if (Object.keys(accounts).length === 0) localStorage.removeItem(KEY)
    else localStorage.setItem(KEY, JSON.stringify({ v: 2, accounts }))
  } catch {
    // Private browsing: the owner knocks like anyone else.
  }
}

export function rememberHostToken(account: string, roomId: string, hostToken: string): void {
  const stored = read()
  const tokens = { ...(stored.accounts[account] ?? {}) }
  if (tokens[roomId] === hostToken) return
  // Re-inserted last, so the newest survive the limit.
  delete tokens[roomId]
  tokens[roomId] = hostToken
  write({ v: 2, accounts: { ...stored.accounts, [account]: tokens } })
}

export function forgetHostToken(account: string, roomId: string): void {
  const stored = read()
  const tokens = stored.accounts[account]
  if (!tokens || !(roomId in tokens)) return
  delete tokens[roomId]
  write(stored)
}

/** On signing out: this browser no longer hosts that account's meetings. */
export function forgetAccountHostTokens(account: string): void {
  const stored = read()
  if (!(account in stored.accounts)) return
  delete stored.accounts[account]
  write(stored)
}

/** An account's host token for a meeting in this browser, if it has one. */
export function hostTokenFor(account: string, roomId: string): string | null {
  return read().accounts[account]?.[roomId] ?? null
}

/**
 * The account whose host tokens this page may use: the one signed in here,
 * once the server confirms that sign-in is still live (it may have ended in
 * another app, which leaves the stored session behind). Null otherwise; a
 * sign-in found to be gone takes its tokens with it.
 */
export async function verifiedHostAccount(): Promise<string | null> {
  const persisted = readPersisted()
  if (!persisted) return null
  try {
    const { sessionId } = await refreshAccessToken()
    if (sessionId === persisted.sessionId) return persisted.userId
  } catch {
    // Signed out, expired or unreachable: not confirmed.
  }
  return null
}
