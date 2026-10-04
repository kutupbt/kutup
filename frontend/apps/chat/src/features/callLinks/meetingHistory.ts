// The meetings joined from this browser, newest first, so a person can find
// one again and rejoin.
//
// A meeting opens at `/call`, outside the app's sign-in, so the page that
// knows a stay ended has no account to put it in. It leaves the stay here,
// in this browser's storage. The signed-in app picks it up from here and
// moves it into the account's own list (`joinedMeetings.ts`), which every
// device of the account sees. For someone without an account, here is where
// the list stays.

const KEY = 'kutup-meeting-history'
const ACCOUNT_KEY = 'kutup-meeting-account'
const LIMIT = 30

export interface JoinedMeeting {
  /** 32 lowercase hex characters: the same stay recorded twice is one. */
  id: string
  /** The part of the link after `#`: what rejoining needs. */
  fragment: string
  roomId: string
  title: string
  joinedAtMs: number
  /** How long the stay lasted. */
  seconds: number
  /** The account signed in to Chat in this browser when it was joined. */
  account?: string
}

function newId(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

function isEntry(value: unknown): value is Omit<JoinedMeeting, 'id'> & { id?: string } {
  if (!value || typeof value !== 'object') return false
  const entry = value as Record<string, unknown>
  return (
    (entry.id === undefined || (typeof entry.id === 'string' && /^[0-9a-f]{32}$/.test(entry.id))) &&
    typeof entry.fragment === 'string' &&
    /^[A-Za-z0-9_-]{44}$/.test(entry.fragment) &&
    typeof entry.roomId === 'string' &&
    typeof entry.title === 'string' &&
    typeof entry.joinedAtMs === 'number' &&
    typeof entry.seconds === 'number' &&
    (entry.account === undefined || typeof entry.account === 'string')
  )
}

export function joinedMeetings(): JoinedMeeting[] {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(KEY) ?? '[]')
    if (!Array.isArray(parsed)) return []
    const entries = parsed.filter(isEntry).slice(0, LIMIT)
    // Stays recorded before they had ids get one now, and keep it.
    if (entries.every((entry) => entry.id !== undefined)) return entries as JoinedMeeting[]
    const named = entries.map((entry) => ({ ...entry, id: entry.id ?? newId() }))
    localStorage.setItem(KEY, JSON.stringify(named))
    return named
  } catch {
    return []
  }
}

function store(entries: JoinedMeeting[]): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(entries.slice(0, LIMIT)))
    window.dispatchEvent(new Event('kutup-meeting-history'))
  } catch {
    // Private browsing: there is simply no history.
  }
}

/**
 * Say which account is signed in to Chat in this browser (null: none), so
 * a stay joined meanwhile goes to that account's list and no other's.
 */
export function setHistoryAccount(userId: string | null): void {
  try {
    if (userId) localStorage.setItem(ACCOUNT_KEY, userId)
    else localStorage.removeItem(ACCOUNT_KEY)
  } catch {
    // Private browsing: stays are simply not tied to an account.
  }
}

function historyAccount(): string | undefined {
  try {
    return localStorage.getItem(ACCOUNT_KEY) ?? undefined
  } catch {
    return undefined
  }
}

/** Record a meeting this browser just left. */
export function recordJoinedMeeting(entry: Omit<JoinedMeeting, 'id' | 'account'>): void {
  const account = historyAccount()
  store([{ ...entry, id: newId(), ...(account ? { account } : {}) }, ...joinedMeetings()])
}

export function forgetJoinedMeetings(ids: ReadonlySet<string>): void {
  const entries = joinedMeetings()
  const kept = entries.filter((entry) => !ids.has(entry.id))
  if (kept.length !== entries.length) store(kept)
}

/** Notified when the history changes, in this tab or another. */
export function subscribeJoinedMeetings(listener: () => void): () => void {
  window.addEventListener('kutup-meeting-history', listener)
  window.addEventListener('storage', listener)
  return () => {
    window.removeEventListener('kutup-meeting-history', listener)
    window.removeEventListener('storage', listener)
  }
}
