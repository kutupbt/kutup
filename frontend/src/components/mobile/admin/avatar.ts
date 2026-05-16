/**
 * Avatar helpers used by the mobile admin's user rows + user-detail header.
 * Ported from the Claude Design handoff (`kutup-admin-mobile.html`); shared
 * across the mobile admin so the colour assignment for a given username
 * stays stable everywhere it appears.
 */

/** Hash a username into one of 8 OKLCH hues. Stable per username. */
export function avatarColor(name: string): string {
  const hues = [220, 282, 152, 55, 348, 200, 32, 175]
  let h = 0
  for (let i = 0; i < name.length; i++) {
    h = (h + name.charCodeAt(i) * 7) % hues.length
  }
  return `oklch(0.55 0.16 ${hues[h]})`
}

/** First 1–2 letters of a username (or email-local-part), uppercased. */
export function initials(name: string): string {
  return name
    .replace(/@.*/, '')
    .split(/[._\-\s]+/)
    .slice(0, 2)
    .map((s) => s[0]?.toUpperCase() ?? '')
    .join('')
}
