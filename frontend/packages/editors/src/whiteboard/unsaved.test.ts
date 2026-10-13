import { describe, expect, it } from 'vitest'
import { hasLocalChanges } from './unsaved'

describe('a whiteboard’s unsaved drawing', () => {
  const seen = new Map([['a', 3], ['b', 1]])

  it('is a new or newer element than this tab sent or received', () => {
    expect(hasLocalChanges([{ id: 'a', version: 3 }, { id: 'b', version: 1 }], seen)).toBe(false)
    expect(hasLocalChanges([{ id: 'a', version: 4 }], seen)).toBe(true)
    expect(hasLocalChanges([{ id: 'c', version: 1 }], seen)).toBe(true)
  })

  it('is not an element merged from someone else (recorded as seen)', () => {
    expect(hasLocalChanges([{ id: 'b', version: 1 }], seen)).toBe(false)
    expect(hasLocalChanges([], seen)).toBe(false)
  })
})
