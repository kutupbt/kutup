import type { BackupRecordSealer } from './backup-store'

/**
 * Tests only: a reversible stand-in for the Rust sealing, bound to each
 * value's name the way the real AEAD is, and unreadable as plain JSON.
 */
export const testSealer: BackupRecordSealer = {
  sealValues: (entries) =>
    entries.map(({ name, value }) => new TextEncoder().encode(`${name}|${btoa(JSON.stringify(value))}`)),
  openValues: <T>(entries: readonly { name: string; sealed: Uint8Array }[]) =>
    entries.map(({ name, sealed }) => {
      const [bound, body] = new TextDecoder().decode(sealed).split('|')
      return bound === name && body !== undefined ? (JSON.parse(atob(body)) as T) : undefined
    }),
}
