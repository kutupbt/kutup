import { describe, expect, it } from 'vitest'
import { schedulable, scheduleSuggestions, snoozeChoices } from './schedule'

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

describe('snooze', () => {
  it('offers Proton’s four mornings', () => {
    const wednesday = new Date(2026, 9, 14, 15, 30)
    expect(snoozeChoices(wednesday).map((c) => [c.kind, c.at])).toEqual([
      ['tomorrow', new Date(2026, 9, 15, 9, 0)],
      ['later', new Date(2026, 9, 16, 9, 0)],
      ['weekend', new Date(2026, 9, 17, 9, 0)],
      ['nextweek', new Date(2026, 9, 19, 9, 0)],
    ])
    // On a Saturday, the weekend is the next one.
    expect(snoozeChoices(new Date(2026, 9, 17, 10, 0))[2].at).toEqual(new Date(2026, 9, 24, 9, 0))
  })
})
