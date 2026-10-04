// The meetings an account joined from this browser, on their way to the
// account's list.
//
// A meeting opens at `/call`, outside the app's sign-in, so the page that
// knows a stay ended cannot put it in the account's list itself (it has no
// account key to seal it with). When someone is signed in to Kutup in this
// browser, it leaves the stay here, in this browser's storage, tagged with
// that account. The signed-in app picks it up from here and moves it into
// the account's own list (`joinedMeetings.ts`), which every device of the
// account sees. A stay joined while nobody is signed in is not kept at all:
// it belongs to no account, and on a shared computer it would otherwise end
// up in the list of whoever signs in next.

const KEY = 'kutup-meeting-history'
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
  /** The account signed in to Kutup in this browser when it was joined. */
  account: string
}

function newId(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

function isEntry(value: unknown): value is JoinedMeeting {
  if (!value || typeof value !== 'object') return false
  const entry = value as Record<string, unknown>
  return (
    typeof entry.id === 'string' &&
    /^[0-9a-f]{32}$/.test(entry.id) &&
    typeof entry.fragment === 'string' &&
    /^[A-Za-z0-9_-]{44}$/.test(entry.fragment) &&
    typeof entry.roomId === 'string' &&
    typeof entry.title === 'string' &&
    typeof entry.joinedAtMs === 'number' &&
    typeof entry.seconds === 'number' &&
    typeof entry.account === 'string' &&
    entry.account !== ''
  )
}

export function joinedMeetings(): JoinedMeeting[] {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(KEY) ?? '[]')
    return Array.isArray(parsed) ? parsed.filter(isEntry).slice(0, LIMIT) : []
  } catch {
    return []
  }
}

function store(entries: JoinedMeeting[]): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(entries.slice(0, LIMIT)))
    window.dispatchEvent(new Event('kutup-meeting-history'))
  } catch {
    // Private browsing: the stay does not reach the account.
  }
}

/** Record a meeting the account signed in here (`account`) just left. */
export function recordJoinedMeeting(entry: Omit<JoinedMeeting, 'id' | 'account'>, account: string): void {
  store([{ ...entry, id: newId(), account }, ...joinedMeetings()])
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
