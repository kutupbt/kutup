import list from './trackers.json'

// Known tracking pixels (docs/plans/mail-parity.md, P5): the same list the
// image proxy refuses (`mail_images.rs`, whose test reads this file), checked
// here so nothing is sent for an image that is never loaded.

interface Tracker {
  host: string
  path: string
  provider: string
}

const TRACKERS: readonly Tracker[] = list

/** The provider of a known tracking pixel at `url`, if it is one. */
export function trackerOf(url: string): string | null {
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return null
  }
  const host = parsed.hostname.replace(/\.$/, '').toLowerCase()
  const found = TRACKERS.find((t) => (host === t.host || host.endsWith(`.${t.host}`)) && (!t.path || parsed.pathname.startsWith(t.path)))
  return found?.provider ?? null
}
