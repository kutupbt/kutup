// The meetings this browser joined, newest first, so a person can find one
// again and rejoin. It is kept only here, in this browser's storage: the
// server has no record of who joined what, and an account's other devices
// do not see it.

const KEY = 'kutup-meeting-history'
const LIMIT = 30

export interface JoinedMeeting {
  /** The part of the link after `#`: what rejoining needs. */
  fragment: string
  roomId: string
  title: string
  joinedAtMs: number
  /** How long this browser stayed in it. */
  seconds: number
}

function isEntry(value: unknown): value is JoinedMeeting {
  if (!value || typeof value !== 'object') return false
  const entry = value as Record<string, unknown>
  return (
    typeof entry.fragment === 'string' &&
    /^[A-Za-z0-9_-]{44}$/.test(entry.fragment) &&
    typeof entry.roomId === 'string' &&
    typeof entry.title === 'string' &&
    typeof entry.joinedAtMs === 'number' &&
    typeof entry.seconds === 'number'
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
    // Private browsing: there is simply no history.
  }
}

/** Record a meeting this browser just left. */
export function recordJoinedMeeting(entry: JoinedMeeting): void {
  store([entry, ...joinedMeetings()])
}

export function forgetJoinedMeeting(entry: JoinedMeeting): void {
  store(joinedMeetings().filter((other) => !(other.roomId === entry.roomId && other.joinedAtMs === entry.joinedAtMs)))
}

export function clearJoinedMeetings(): void {
  store([])
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
