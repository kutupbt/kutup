// Passwords and passphrases from the browser's cryptographic random source,
// without modulo bias.

export interface GeneratorOptions {
  length: number
  lower: boolean
  upper: boolean
  digits: boolean
  symbols: boolean
  /** Leaves out 0/O, 1/l/I and the like. */
  avoidLookAlikes: boolean
}

export const DEFAULT_OPTIONS: GeneratorOptions = {
  length: 20,
  lower: true,
  upper: true,
  digits: true,
  symbols: true,
  avoidLookAlikes: false,
}

const SETS = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!#$%&*+-.:;=?@^_~',
} as const
const LOOK_ALIKES = new Set('0O1lI|'.split(''))

/** A uniformly random integer in [0, n). */
export function randomBelow(n: number): number {
  if (n <= 0 || n > 2 ** 32) throw new Error('out of range')
  const limit = Math.floor(2 ** 32 / n) * n
  const word = new Uint32Array(1)
  for (;;) {
    crypto.getRandomValues(word)
    if (word[0] < limit) return word[0] % n
  }
}

/** A password with at least one character of each chosen set. */
export function generatePassword(options: GeneratorOptions): string {
  const sets = (Object.keys(SETS) as (keyof typeof SETS)[])
    .filter((name) => options[name])
    .map((name) => SETS[name].split('').filter((c) => !options.avoidLookAlikes || !LOOK_ALIKES.has(c)))
  if (sets.length === 0) throw new Error('choose at least one kind of character')
  const length = Math.max(options.length, sets.length)
  const all = sets.flat()
  const chars = sets.map((set) => set[randomBelow(set.length)])
  while (chars.length < length) chars.push(all[randomBelow(all.length)])
  // Fisher–Yates, so the required characters are anywhere.
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomBelow(i + 1)
    ;[chars[i], chars[j]] = [chars[j], chars[i]]
  }
  return chars.join('')
}

/** Bits of entropy of a password drawn this way (an estimate for the strength meter). */
export function entropyBits(options: GeneratorOptions): number {
  const size = (Object.keys(SETS) as (keyof typeof SETS)[])
    .filter((name) => options[name])
    .reduce((sum, name) => sum + SETS[name].split('').filter((c) => !options.avoidLookAlikes || !LOOK_ALIKES.has(c)).length, 0)
  return size > 0 ? Math.floor(options.length * Math.log2(size)) : 0
}

/** A rough strength of any password: weak, fair, strong. */
export function strengthOf(password: string): 'weak' | 'fair' | 'strong' {
  if (!password) return 'weak'
  let size = 0
  if (/[a-z]/.test(password)) size += 26
  if (/[A-Z]/.test(password)) size += 26
  if (/[0-9]/.test(password)) size += 10
  if (/[^a-zA-Z0-9]/.test(password)) size += 33
  const bits = password.length * Math.log2(Math.max(size, 2))
  return bits >= 80 ? 'strong' : bits >= 50 ? 'fair' : 'weak'
}

/** The characters of a generated vault key: Crockford's base32, lowercase (no i, l, o, u). */
const VAULT_KEY_ALPHABET = '0123456789abcdefghjkmnpqrstvwxyz'

/**
 * A vault key Kutup Pass generates (docs/plans/pass.md, "Vault keys"): 25
 * characters of a 32-letter alphabet, 125 bits, in groups of five, easy to
 * read out and paste into a KeePass app.
 */
export function randomVaultKey(): string {
  // 32 divides 256: a byte's low five bits carry no bias.
  const bytes = crypto.getRandomValues(new Uint8Array(25))
  const chars = Array.from(bytes, (byte) => VAULT_KEY_ALPHABET[byte & 31])
  return [0, 5, 10, 15, 20].map((at) => chars.slice(at, at + 5).join('')).join('-')
}
