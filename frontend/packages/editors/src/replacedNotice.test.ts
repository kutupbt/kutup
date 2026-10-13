import { describe, expect, it } from 'vitest'
import { lostUnsentEdits } from './replacedNotice'

describe('the notice when a document is replaced under a tab', () => {
  it('is shown only when the reset drops edits not yet stored', () => {
    expect(lostUnsentEdits(true, 2)).toBe(true)
    // Replaced, but everything this tab made was stored: nothing lost.
    expect(lostUnsentEdits(true, 0)).toBe(false)
    // Reopened for another reason (a session started elsewhere): the queue is kept.
    expect(lostUnsentEdits(false, 3)).toBe(false)
  })

  it('counts a whiteboard drawing not saved yet, even with every frame sent', () => {
    expect(lostUnsentEdits(true, 0, true)).toBe(true)
    expect(lostUnsentEdits(false, 0, true)).toBe(false)
    expect(lostUnsentEdits(true, 0, false)).toBe(false)
  })
})
