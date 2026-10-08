import { act, renderHook } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { ConflictPolicy, useNameConflict, type ConflictQuestion } from './nameConflicts'

/** Ask inside `act`, so the hook sees the question. */
function ask<T>(start: () => Promise<T>): Promise<T> {
  let pending!: Promise<T>
  act(() => {
    pending = start()
    pending.catch(() => {})
  })
  return pending
}

const question = (over: Partial<ConflictQuestion> = {}): Omit<ConflictQuestion, 'more'> => ({
  name: 'a.txt',
  folderName: 'Docs',
  holder: 'file',
  keptAs: 'a (2).txt',
  canReplace: true,
  ...over,
})

describe('name conflicts', () => {
  it('asks one question at a time and remembers an answer applied to all', async () => {
    const { result } = renderHook(() => useNameConflict())
    const policy = new ConflictPolicy(3)
    const first = ask(() => policy.choose(question()))
    expect(result.current?.question.more).toBe(true)
    act(() => result.current!.answer({ choice: 'keepBoth', all: true }))
    expect(await first).toBe('keepBoth')
    expect(result.current).toBeNull()
    // Remembered: not asked again.
    expect(await policy.choose(question({ name: 'b.txt' }))).toBe('keepBoth')
    expect(result.current).toBeNull()
  })

  it('asks again where the remembered choice does not fit', async () => {
    const { result } = renderHook(() => useNameConflict())
    const policy = new ConflictPolicy(2)
    const first = ask(() => policy.choose(question()))
    act(() => result.current!.answer({ choice: 'replace', all: true }))
    expect(await first).toBe('replace')
    // A folder holds this one's name: it cannot be replaced.
    const second = ask(() => policy.choose(question({ holder: 'folder', canReplace: false })))
    expect(result.current?.question.holder).toBe('folder')
    act(() => result.current!.answer({ choice: 'skip', all: false }))
    expect(await second).toBe('skip')
  })

  it('offers no "apply to all" for one item, and gives up when cancelled', async () => {
    const { result } = renderHook(() => useNameConflict())
    const controller = new AbortController()
    const asked = ask(() => new ConflictPolicy(1).choose(question(), controller.signal))
    expect(result.current?.question.more).toBe(false)
    act(() => controller.abort())
    await expect(asked).rejects.toMatchObject({ name: 'AbortError' })
    expect(result.current).toBeNull()
  })
})
