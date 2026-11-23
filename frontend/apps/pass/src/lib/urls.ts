/**
 * Keepass2Android's and KeePassXC's extra URLs: custom fields named
 * `KP2A_URL`, `KP2A_URL_1`, … (KeePassXC `Entry::getAdditionalUrls`).
 */
export const ADDITIONAL_URL_PREFIX = 'KP2A_URL'

export function isAdditionalUrl(key: string): boolean {
  return key.startsWith(ADDITIONAL_URL_PREFIX)
}

/**
 * A URL the page may open in a new tab: http or https only, so a field
 * holding `javascript:` or `data:` is never a link.
 */
export function openableUrl(value: string): string | null {
  const url = value.trim()
  return /^https?:\/\/\S+$/i.test(url) ? url : null
}
