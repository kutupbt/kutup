import { describe, expect, it } from 'vitest'
import { schedulable, scheduleSuggestions } from './schedule'

describe('scheduled send', () => {
  it('suggests tomorrow and Monday mornings, as Proton', () => {
    // A Wednesday.
    const wednesday = new Date(2026, 9, 14, 15, 30)
    const [tomorrow, monday] = scheduleSuggestions(wednesday)
    expect(tomorrow.kind).toBe('tomorrow')
    expect(tomorrow.at).toEqual(new Date(2026, 9, 15, 8, 0))
    expect(monday.at).toEqual(new Date(2026, 9, 19, 8, 0))
    // On a Sunday, Monday is tomorrow: one choice.
    expect(scheduleSuggestions(new Date(2026, 9, 18, 10, 0))).toHaveLength(1)
  })

  it('takes a minute to 90 days ahead', () => {
    const now = new Date(2026, 9, 14, 12, 0)
    expect(schedulable(new Date(now.getTime() + 30_000), now)).toBe(false)
    expect(schedulable(new Date(now.getTime() + 2 * 60_000), now)).toBe(true)
    expect(schedulable(new Date(now.getTime() + 91 * 86_400_000), now)).toBe(false)
  })
})
