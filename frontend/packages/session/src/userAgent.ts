/**
 * A browser and system from a User-Agent string, the same way the server
 * parses it (crates/kutup-server/src/client_family.rs): the same markers in
 * the same order, checked against one list of vectors (userAgent.vectors.json).
 */
export interface ClientFamily {
  browser: string | null
  browserMajor: number | null
  os: string | null
}

/** Order matters: browsers built on another name it too (Edge says Chrome and Safari; Chrome says Safari). */
const BROWSERS: [marker: string, name: string][] = [
  ['kutup-cli/', 'Kutup CLI'],
  ['EdgA/', 'Edge'],
  ['EdgiOS/', 'Edge'],
  ['Edg/', 'Edge'],
  ['OPR/', 'Opera'],
  ['SamsungBrowser/', 'Samsung Internet'],
  ['FxiOS/', 'Firefox'],
  ['Firefox/', 'Firefox'],
  ['CriOS/', 'Chrome'],
  ['Chrome/', 'Chrome'],
]

/** The major version after `marker` (`Firefox/` in `Firefox/128.0`). */
function majorAfter(ua: string, marker: string): number | null {
  const start = ua.indexOf(marker)
  if (start < 0) return null
  const digits = /^\d+/.exec(ua.slice(start + marker.length))
  if (!digits) return null
  const major = Number(digits[0])
  return major <= 0xffff ? major : null
}

function osOf(ua: string): string | null {
  if (/iPhone|iPad|iPod/.test(ua)) return 'iOS'
  if (ua.includes('Android')) return 'Android'
  if (ua.includes('CrOS')) return 'ChromeOS'
  if (ua.includes('Windows')) return 'Windows'
  if (ua.includes('Mac OS X') || ua.includes('Macintosh')) return 'macOS'
  if (ua.includes('Linux') || ua.includes('X11')) return 'Linux'
  return null
}

/** The browser (with its major version) and system a User-Agent names; nulls for what it doesn't. */
export function parseUserAgent(ua: string | null): ClientFamily {
  if (!ua) return { browser: null, browserMajor: null, os: null }
  const known = BROWSERS.find(([marker]) => ua.includes(marker))
  if (known) return { browser: known[1], browserMajor: majorAfter(ua, known[0]), os: osOf(ua) }
  if (ua.includes('Safari/') && ua.includes('Version/')) {
    return { browser: 'Safari', browserMajor: majorAfter(ua, 'Version/'), os: osOf(ua) }
  }
  return { browser: null, browserMajor: null, os: osOf(ua) }
}

/** "Firefox 128 on Linux", as feedback sends it and the server accepts it; null when nothing is known. */
export function describeClientFamily(family: ClientFamily): string | null {
  const browser = family.browser
    ? family.browserMajor !== null && family.browser !== 'Kutup CLI'
      ? `${family.browser} ${family.browserMajor}`
      : family.browser
    : null
  return [browser, family.os].filter(Boolean).join(' on ') || null
}
