import { loadServerSettings } from '@kutup/session/apps'
import type { KdfInput, KdfMinimums } from '../vault/types'

/** The server's own defaults, for a server that doesn't publish its minimums. */
export const DEFAULT_MINIMUMS: KdfMinimums = { argon2MemoryMib: 64, argon2Iterations: 2, aesKdfRounds: 100_000 }
/** The most any device is asked to do (kutup_pass::edit::MAX_*). */
export const KDF_LIMITS = { argon2MemoryMib: 2048, argon2Iterations: 10_000, argon2Parallelism: 16, aesKdfRounds: 1_000_000_000 }
/** How long opening should take: KeePassXC's "Benchmark 1 s". */
export const TARGET_MS = 1000

/** The weakest key derivation this server lets a vault be set to. */
export async function loadKdfMinimums(): Promise<KdfMinimums> {
  const settings = await loadServerSettings<{ passKdfMinimums?: Partial<KdfMinimums> }>()
  const published = settings.passKdfMinimums ?? {}
  const whole = (value: unknown, fallback: number) => (typeof value === 'number' && Number.isInteger(value) && value >= 1 ? value : fallback)
  return {
    argon2MemoryMib: whole(published.argon2MemoryMib, DEFAULT_MINIMUMS.argon2MemoryMib),
    argon2Iterations: whole(published.argon2Iterations, DEFAULT_MINIMUMS.argon2Iterations),
    aesKdfRounds: whole(published.aesKdfRounds, DEFAULT_MINIMUMS.aesKdfRounds),
  }
}

/** Whether `kdf` is at least `minimums` (as the core checks it). */
export function meetsMinimums(kdf: KdfInput, minimums: KdfMinimums): boolean {
  if (kdf.kind === 'aesKdf') return kdf.rounds >= minimums.aesKdfRounds
  return kdf.memoryMib >= minimums.argon2MemoryMib && kdf.iterations >= minimums.argon2Iterations
}

/** What makes `kdf` out of range, if anything: a key for the message. */
export function kdfProblem(kdf: KdfInput, minimums: KdfMinimums): 'belowMinimum' | 'outOfRange' | null {
  const within = (value: number, max: number) => Number.isInteger(value) && value >= 1 && value <= max
  if (kdf.kind === 'aesKdf') {
    if (!within(kdf.rounds, KDF_LIMITS.aesKdfRounds)) return 'outOfRange'
  } else if (
    !within(kdf.memoryMib, KDF_LIMITS.argon2MemoryMib) ||
    !within(kdf.iterations, KDF_LIMITS.argon2Iterations) ||
    !within(kdf.parallelism, KDF_LIMITS.argon2Parallelism)
  ) {
    return 'outOfRange'
  }
  return meetsMinimums(kdf, minimums) ? null : 'belowMinimum'
}

/**
 * The passes (Argon2) or rounds (AES-KDF) that take about `TARGET_MS` on
 * this device, from one timed run of `kdf` as it is: the time grows with
 * them in step. Never below the minimums nor above the limits.
 */
export function scaledForTarget(kdf: KdfInput, measuredMs: number, minimums: KdfMinimums): KdfInput {
  const factor = TARGET_MS / Math.max(measuredMs, 1)
  const clamp = (value: number, min: number, max: number) => Math.min(max, Math.max(min, Math.round(value)))
  if (kdf.kind === 'aesKdf') return { kind: 'aesKdf', rounds: clamp(kdf.rounds * factor, minimums.aesKdfRounds, KDF_LIMITS.aesKdfRounds) }
  return { ...kdf, iterations: clamp(kdf.iterations * factor, minimums.argon2Iterations, KDF_LIMITS.argon2Iterations) }
}

/** A sensible starting point when the algorithm changes. */
export function defaultKdf(kind: KdfInput['kind'], minimums: KdfMinimums): KdfInput {
  if (kind === 'aesKdf') return { kind, rounds: Math.max(minimums.aesKdfRounds, 2_000_000) }
  return { kind, memoryMib: Math.max(minimums.argon2MemoryMib, 64), iterations: Math.max(minimums.argon2Iterations, 10), parallelism: 2 }
}
