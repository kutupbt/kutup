import { describe, expect, it } from 'vitest'
import { ChatServiceError, groupFailure } from './service'

describe('groupFailure', () => {
  it('says a refusal by its code, from the home or from the local check', () => {
    expect((groupFailure(new Error('the group home refused the change: avatarTooLarge')) as ChatServiceError).code).toBe('groupAvatarTooLarge')
    expect((groupFailure(new Error('group change refused: notAllowed')) as ChatServiceError).code).toBe('groupNotAllowed')
    expect((groupFailure(new Error('the group home refused the change: somethingNew')) as ChatServiceError).code).toBe('groupRefused')
    expect((groupFailure(new Error("the group's server can't be reached: Unreachable")) as ChatServiceError).code).toBe('groupUnreachable')
  })

  it('leaves anything else as it was', () => {
    const other = new Error('database locked')
    expect(groupFailure(other)).toBe(other)
  })
})
