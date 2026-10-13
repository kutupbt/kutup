// The account's session version (docs/api.md, "Session version"): every
// authenticated answer carries `X-Kutup-Session-Version`, a digest of the
// account's security state. Each app lives on its own origin and cannot hear
// the others, so this is how a password, 2FA, role or key binding change made
// elsewhere reaches it: on a change, the app reads its account again, and a
// key binding that is no longer the one its keys carry ends the session.

export const SESSION_VERSION_HEADER = 'x-kutup-session-version'

let seen: string | null = null
let checking: Promise<void> | null = null
let onChange: (() => Promise<void>) | null = null

/** What to do when the version changes (set once by the session package). */
export function setSessionVersionHandler(handler: () => Promise<void>): void {
  onChange = handler
}

/** Notes the version an answer carried; a change runs the handler once. */
export function noteSessionVersion(version: unknown): void {
  if (typeof version !== 'string' || !version) return
  if (seen === null) {
    seen = version
    return
  }
  if (version === seen) return
  seen = version
  if (!onChange || checking) return
  checking = onChange()
    .catch(() => undefined)
    .finally(() => {
      checking = null
    })
}

/** A new sign-in starts from whatever the server says next. */
export function resetSessionVersion(): void {
  seen = null
}
