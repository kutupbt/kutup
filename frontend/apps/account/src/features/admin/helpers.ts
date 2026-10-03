const GIB = 1024 ** 3

/** Quotas are entered in GiB (what they are enforced in) and stored in bytes. */
export function bytesToGib(bytes: number): number {
  return Math.round((bytes / GIB) * 100) / 100
}

export function gibToBytes(gib: number): number {
  return Math.round(gib * GIB)
}

/** No 0/O, 1/l/I: the password is read aloud or copied by hand to its owner. */
const ALPHABET = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'

/**
 * A temporary password for a new or wiped account: 20 characters, ~115 bits.
 * It only has to survive until the user's first sign-in, where they choose
 * their own and their keys are created on their device.
 */
export function generateTempPassword(length = 20): string {
  const out: string[] = []
  const random = new Uint32Array(1)
  // Rejection sampling keeps every character equally likely.
  const limit = Math.floor(0x1_0000_0000 / ALPHABET.length) * ALPHABET.length
  while (out.length < length) {
    crypto.getRandomValues(random)
    if (random[0] < limit) out.push(ALPHABET[random[0] % ALPHABET.length])
  }
  return out.join('')
}
