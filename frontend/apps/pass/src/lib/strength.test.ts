import { describe, expect, it } from 'vitest'
import { strengthOfScore } from './strength'

describe('strength steps', () => {
  it('groups zxcvbn scores as the report does', () => {
    expect([0, 1, 2, 3, 4].map(strengthOfScore)).toEqual(['weak', 'weak', 'fair', 'strong', 'strong'])
  })
})
