import { describe, expect, it } from 'vitest'
import { SaveTracker, hasLocalChanges } from './unsaved'

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

describe('SaveTracker', () => {
  it('counts drawing as unsaved until its save is stored', () => {
    const saves = new SaveTracker()
    expect(saves.unsaved).toBe(false)
    saves.markChanged()
    const settle = saves.beginSave()
    // Serialised, not stored yet: a reset now would lose it.
    expect(saves.unsaved).toBe(true)
    settle(true)
    expect(saves.unsaved).toBe(false)
  })

  it('a failed save leaves the drawing unsaved', () => {
    const saves = new SaveTracker()
    saves.markChanged()
    saves.beginSave()(false)
    expect(saves.unsaved).toBe(true)
  })

  it('drawing during a save stays unsaved after it is stored', () => {
    const saves = new SaveTracker()
    saves.markChanged()
    const settle = saves.beginSave()
    saves.markChanged()
    settle(true)
    expect(saves.unsaved).toBe(true)
  })
})
