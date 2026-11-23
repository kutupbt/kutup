import { describe, expect, it } from 'vitest'
import { DEFAULT_MINIMUMS, defaultKdf, kdfProblem, meetsMinimums, scaledForTarget } from './kdf'

const argon = { kind: 'argon2id' as const, memoryMib: 64, iterations: 10, parallelism: 2 }

describe('vault key derivation', () => {
  it('checks the minimums as the core does', () => {
    expect(meetsMinimums(argon, DEFAULT_MINIMUMS)).toBe(true)
    expect(meetsMinimums({ ...argon, memoryMib: 32 }, DEFAULT_MINIMUMS)).toBe(false)
    expect(meetsMinimums({ ...argon, iterations: 1 }, DEFAULT_MINIMUMS)).toBe(false)
    expect(meetsMinimums({ kind: 'aesKdf', rounds: 99_999 }, DEFAULT_MINIMUMS)).toBe(false)
  })

  it('names what is wrong: out of range before below the minimum', () => {
    expect(kdfProblem(argon, DEFAULT_MINIMUMS)).toBeNull()
    expect(kdfProblem({ ...argon, memoryMib: 4096 }, DEFAULT_MINIMUMS)).toBe('outOfRange')
    expect(kdfProblem({ ...argon, parallelism: 0 }, DEFAULT_MINIMUMS)).toBe('outOfRange')
    expect(kdfProblem({ ...argon, iterations: 1.5 }, DEFAULT_MINIMUMS)).toBe('outOfRange')
    expect(kdfProblem({ ...argon, memoryMib: 16 }, DEFAULT_MINIMUMS)).toBe('belowMinimum')
  })

  it('scales passes or rounds to about a second, within the bounds', () => {
    expect(scaledForTarget(argon, 250, DEFAULT_MINIMUMS)).toEqual({ ...argon, iterations: 40 })
    expect(scaledForTarget(argon, 100_000, DEFAULT_MINIMUMS)).toEqual({ ...argon, iterations: 2 })
    expect(scaledForTarget(argon, 0.001, DEFAULT_MINIMUMS)).toEqual({ ...argon, iterations: 10_000 })
    expect(scaledForTarget({ kind: 'aesKdf', rounds: 1_000_000 }, 100, DEFAULT_MINIMUMS)).toEqual({ kind: 'aesKdf', rounds: 10_000_000 })
  })

  it('starts a new algorithm at or above the minimums', () => {
    expect(defaultKdf('argon2d', { ...DEFAULT_MINIMUMS, argon2MemoryMib: 256 })).toEqual({ kind: 'argon2d', memoryMib: 256, iterations: 10, parallelism: 2 })
    expect(defaultKdf('aesKdf', DEFAULT_MINIMUMS)).toEqual({ kind: 'aesKdf', rounds: 2_000_000 })
  })
})
