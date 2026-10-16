import { describe, expect, it } from 'vitest'
import { insertMention, mentionQuery, resolveMentions, splitMentions } from './mentions'
import { parseAccount } from '@kutup/chat-core/identity'

const acct = (key: string) => parseAccount(key)!

describe('mentions', () => {
  it('finds the @query being typed', () => {
    expect(mentionQuery('hi @al', 6)).toEqual({ start: 3, query: 'al' })
    expect(mentionQuery('@', 1)).toEqual({ start: 0, query: '' })
    expect(mentionQuery('mail a@b', 8)).toBeNull()
    expect(mentionQuery('hi @al there', 12)).toBeNull()
  })

  it('inserts the picked name in place of the query', () => {
    expect(insertMention('hi @al!', 3, 6, '@Ali')).toEqual({ text: 'hi @Ali !', caret: 8 })
  })

  it('resolves picks to UTF-16 ranges and drops edited-away ones', () => {
    const picks = [
      { label: '@Ali', member: acct('aci:00000000-0000-4000-8000-94419b99b12c@a.test') },
      { label: '@Bob', member: acct('aci:00000000-0000-4000-8000-81b637d8fcd2@b.test') },
    ]
    expect(resolveMentions('🙂 @Ali and @Bob', picks)).toEqual([
      { start: 3, length: 4, member: acct('aci:00000000-0000-4000-8000-94419b99b12c@a.test') },
      { start: 12, length: 4, member: acct('aci:00000000-0000-4000-8000-81b637d8fcd2@b.test') },
    ])
    expect(resolveMentions('@Alice and @Bob', picks)).toEqual([{ start: 11, length: 4, member: acct('aci:00000000-0000-4000-8000-81b637d8fcd2@b.test') }])
    // The same person twice: both occurrences.
    const twice = [...picks.slice(0, 1), picks[0]]
    expect(resolveMentions('@Ali, @Ali!', twice)).toEqual([
      { start: 0, length: 4, member: acct('aci:00000000-0000-4000-8000-94419b99b12c@a.test') },
      { start: 6, length: 4, member: acct('aci:00000000-0000-4000-8000-94419b99b12c@a.test') },
    ])
  })

  it('splits text around mentions', () => {
    expect(splitMentions('hi @Ali!', [{ start: 3, length: 4, member: acct('aci:00000000-0000-4000-8000-94419b99b12c@a.test') }])).toEqual([
      { kind: 'text', value: 'hi ' },
      { kind: 'mention', member: 'aci:00000000-0000-4000-8000-94419b99b12c@a.test', value: '@Ali' },
      { kind: 'text', value: '!' },
    ])
    expect(splitMentions('short', [{ start: 3, length: 40, member: acct('aci:00000000-0000-4000-8000-0000000000aa@y.test') }])).toEqual([{ kind: 'text', value: 'short' }])
  })
})
