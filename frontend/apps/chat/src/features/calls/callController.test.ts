import { describe, expect, it } from 'vitest'
import { outcomeOf } from './callController'

describe('outcomeOf', () => {
  it('records answered calls whoever hung up', () => {
    expect(outcomeOf(true, 'hungUp', true)).toBe('answered')
    expect(outcomeOf(false, 'failed', true)).toBe('answered')
  })

  it('words unanswered calls by side', () => {
    expect(outcomeOf(true, 'missed', false)).toBe('missed')
    expect(outcomeOf(true, 'hungUp', false)).toBe('missed')
    expect(outcomeOf(false, 'hungUp', false)).toBe('unanswered')
    expect(outcomeOf(false, 'unanswered', false)).toBe('unanswered')
    expect(outcomeOf(false, 'busy', false)).toBe('busy')
    expect(outcomeOf(true, 'declined', false)).toBe('declined')
  })

  it('leaves calls another device took out of this timeline', () => {
    expect(outcomeOf(true, 'elsewhere', false)).toBeNull()
  })
})
