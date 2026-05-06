// Per-tab identity for the collab editor: a stable random tabId (so two tabs
// of the same user appear as distinct peers in awareness) and a cursor color
// preference (random-from-palette by default, user-customizable).
//
// tabId is sessionStorage-scoped (one per tab session, survives reload).
// color is localStorage-scoped (a tab opened in a fresh window gets the user's
// previous color preference back; user can override at any time).

export const CURSOR_COLORS_20 = [
  '#ef4444', '#f97316', '#f59e0b', '#eab308', '#84cc16',
  '#22c55e', '#10b981', '#14b8a6', '#06b6d4', '#0ea5e9',
  '#3b82f6', '#6366f1', '#8b5cf6', '#a855f7', '#d946ef',
  '#ec4899', '#f43f5e', '#64748b', '#525252', '#0f766e',
]

const TAB_ID_KEY = 'kutup_tab_id_v1'
const COLOR_PREF_KEY = 'kutup_cursor_color_v1'

function randomHex(bytes: number): string {
  const arr = new Uint8Array(bytes)
  crypto.getRandomValues(arr)
  return Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('')
}

/** Stable per-tab identifier. Persisted in sessionStorage, survives reload. */
export function getOrCreateTabId(): string {
  let v = sessionStorage.getItem(TAB_ID_KEY)
  if (!v) {
    v = randomHex(2)
    sessionStorage.setItem(TAB_ID_KEY, v)
  }
  return v
}

/** User's preferred cursor color. Random-from-palette on first call. */
export function getCursorColor(): string {
  let v = localStorage.getItem(COLOR_PREF_KEY)
  if (!v) {
    v = CURSOR_COLORS_20[Math.floor(Math.random() * CURSOR_COLORS_20.length)]
    localStorage.setItem(COLOR_PREF_KEY, v)
  }
  return v
}

export function setCursorColor(hex: string): void {
  localStorage.setItem(COLOR_PREF_KEY, hex)
}

/** Convert "#rrggbb" to an rgba() string with the given alpha — used as the
 *  awareness `colorLight` so y-codemirror.next paints a translucent selection
 *  background that complements the cursor caret. */
export function withAlpha(hex: string, alpha: number): string {
  const r = parseInt(hex.slice(1, 3), 16)
  const g = parseInt(hex.slice(3, 5), 16)
  const b = parseInt(hex.slice(5, 7), 16)
  return `rgba(${r}, ${g}, ${b}, ${alpha})`
}

/** Display name shown over the cursor — appends `#<tabId>` so multiple tabs
 *  of the same user are distinguishable. */
export function buildAwarenessName(username: string | null | undefined): string {
  const tab = getOrCreateTabId()
  return `${username ?? 'anon'} #${tab}`
}

/**
 * Per-tab outbound `sender_seq` start point. The 64-bit sender_seq is
 * partitioned as (tabPrefix << 32) | localCounter. Two tabs of the same
 * user share a `deviceId` (sessionStorage-loaded keypair), so without
 * a per-tab partition both tabs would race on `(file_id, sender_device,
 * sender_seq)` UNIQUE collisions in `file_update_log` — the relay drops
 * one frame on collision, producing the "one-way sync" symptom in xlsx
 * and the silent-drop branch of the notes seed race.
 *
 * `mySenderSeqHigh` from the server's hello tells us the largest
 * sender_seq this device has ever sent; the new tab's prefix MUST be
 * strictly greater so its first counter increment can't collide with
 * any historical row. Re-roll on the (vanishingly rare) collision.
 *
 * Returns a BigInt with bits 32-63 set to a random 32-bit value and
 * bits 0-31 zero (the localCounter slot).
 */
export function randomSenderSeqPrefix(mustExceed: bigint = 0n): bigint {
  const buf = new Uint32Array(1)
  for (;;) {
    crypto.getRandomValues(buf)
    // Mask to 31 bits before shifting. Postgres BIGINT is SIGNED int64;
    // a top-bit-set 32-bit prefix would shift to a value > 2^63 (negative
    // when interpreted as int64), silently breaking MAX(sender_seq)
    // ordering and the (file_id, sender_device, sender_seq) uniqueness
    // semantics. 31 bits gives 2^31 distinct prefixes — collision odds
    // remain negligible.
    const candidate = BigInt(buf[0] & 0x7FFFFFFF) << 32n
    if (candidate > mustExceed) return candidate
    // Vanishingly unlikely. Re-roll.
  }
}
