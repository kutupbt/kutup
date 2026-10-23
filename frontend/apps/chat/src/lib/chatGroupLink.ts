/**
 * Pairwise group links (docs/plans/pairwise-groups.md §11): `/join#<fragment>`,
 * the fragment base64url (no padding) of version 1 ‖ master key (32) ‖
 * password (16) ‖ identity sequence (8) ‖ identity hash (32) ‖ server. The
 * fragment never reaches a server. The core checks it fully; this only tells
 * a group link from other text.
 */
const FIXED_BYTES = 1 + 32 + 16 + 8 + 32

/** The fragment of `url` (or `url` itself, when it is one) if it is a pairwise group link. */
export function chatGroupLinkFragment(url: string): string | null {
  const hash = url.includes('#') ? url.slice(url.indexOf('#') + 1) : url
  if (!/^[A-Za-z0-9_-]+$/.test(hash)) return null
  let bytes: Uint8Array
  try {
    const padded = hash.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (hash.length % 4)) % 4)
    bytes = Uint8Array.from(atob(padded), (c) => c.charCodeAt(0))
  } catch {
    return null
  }
  return bytes.length > FIXED_BYTES && bytes[0] === 1 ? hash : null
}

/**
 * The fragment of `text` when it is a group link URL (`https://…/join#…`,
 * whatever server's Chat app it points at), else `null`.
 */
export function groupLinkFragmentFromUrl(text: string): string | null {
  let url: URL
  try {
    url = new URL(text.trim())
  } catch {
    return null
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null
  if (!/\/join\/?$/.test(url.pathname)) return null
  return chatGroupLinkFragment(url.hash.slice(1))
}

/** The link to share for a group's fragment, on this Chat app. */
export function chatGroupLinkUrl(fragment: string): string {
  return `${window.location.origin}/join#${fragment}`
}
