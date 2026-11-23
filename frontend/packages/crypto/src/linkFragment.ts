// A public link's fragment (docs/plans/api-surface.md §7): `#v1.<key>`, the
// link key as unpadded base64url, behind a format version. Links can't be
// reissued once shared, so a later format (a password-protected link) adds
// `v2.` beside this one rather than changing it. Browsers never send the
// fragment to a server.

import { toBase64Url } from './base64'

const V1 = 'v1.'
const KEY_BYTES = 32

/** What a link's fragment carries: its key, a format this build doesn't read, or nothing usable. */
export type LinkFragment = { kind: 'key'; key: Uint8Array } | { kind: 'newer' } | { kind: 'invalid' }

export function encodeLinkFragment(key: Uint8Array): string {
  if (key.length !== KEY_BYTES) throw new Error('a link key is 32 bytes')
  return `#${V1}${toBase64Url(key)}`
}

export function parseLinkFragment(hash: string): LinkFragment {
  const fragment = hash.startsWith('#') ? hash.slice(1) : hash
  if (/^v[0-9]+\./.test(fragment) && !fragment.startsWith(V1)) return { kind: 'newer' }
  if (!fragment.startsWith(V1)) return { kind: 'invalid' }
  const body = fragment.slice(V1.length)
  if (!/^[A-Za-z0-9_-]{43}$/.test(body)) return { kind: 'invalid' }
  try {
    const padded = body.replace(/-/g, '+').replace(/_/g, '/') + '='
    const binary = atob(padded)
    const key = Uint8Array.from(binary, (char) => char.charCodeAt(0))
    return key.length === KEY_BYTES ? { kind: 'key', key } : { kind: 'invalid' }
  } catch {
    return { kind: 'invalid' }
  }
}
