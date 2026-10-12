import { describe, expect, it } from 'vitest'
import { closeComposer, composerGeneration, openComposer } from './composerState'

describe('the composer slot', () => {
  it('closes only the composer that asks, once another opened', () => {
    openComposer({ kind: 'new' })
    const first = composerGeneration()
    openComposer({ kind: 'new', to: 'ali@kutup.dev' })
    // The first composer's send finishes late: the second stays.
    closeComposer(first)
    expect(composerGeneration()).toBe(first + 1)
    closeComposer(first + 1)
    expect(composerGeneration()).toBe(first + 2)
    // Without a generation (Escape on whatever is open) it always closes.
    openComposer({ kind: 'new' })
    const before = composerGeneration()
    closeComposer()
    expect(composerGeneration()).toBe(before + 1)
  })
})
