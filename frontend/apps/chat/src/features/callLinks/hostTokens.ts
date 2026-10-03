// The host tokens of this account's meetings, for the meeting page.
//
// A meeting opens at `/call`, outside the app's sign-in, so that page has no
// session to derive anything from. The signed-in app, which can derive each
// meeting's host token from the account key, leaves them here for it: in
// this browser's storage, on this origin only. With one, the page lets the
// owner straight into a meeting with a waiting room and shows who is
// waiting. Someone who opens their own meeting in a browser where they are
// not signed in is a guest like any other, and waits.

const KEY = 'kutup-meeting-hosts'
/** As many as an account can have meetings. */
const LIMIT = 50

function read(): Record<string, string> {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(KEY) ?? '{}')
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {}
    return Object.fromEntries(
      Object.entries(parsed as Record<string, unknown>).filter(
        (entry): entry is [string, string] => /^[0-9a-f]{32}$/.test(entry[0]) && typeof entry[1] === 'string',
      ),
    )
  } catch {
    return {}
  }
}

function write(tokens: Record<string, string>): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(Object.fromEntries(Object.entries(tokens).slice(-LIMIT))))
  } catch {
    // Private browsing: the owner knocks like anyone else.
  }
}

export function rememberHostToken(roomId: string, hostToken: string): void {
  const tokens = read()
  if (tokens[roomId] === hostToken) return
  // Re-inserted last, so the newest survive the limit.
  delete tokens[roomId]
  write({ ...tokens, [roomId]: hostToken })
}

export function forgetHostToken(roomId: string): void {
  const tokens = read()
  if (!(roomId in tokens)) return
  delete tokens[roomId]
  write(tokens)
}

/** This browser's host token for a meeting, if its owner is signed in here. */
export function hostTokenFor(roomId: string): string | null {
  return read()[roomId] ?? null
}
