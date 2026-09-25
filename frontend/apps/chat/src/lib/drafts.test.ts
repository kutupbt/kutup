import { beforeEach, describe, expect, it } from 'vitest'
import { clearDrafts, getDraft, setDraft } from './drafts'

describe('drafts', () => {
  beforeEach(() => window.localStorage.clear())

  it('keeps a draft per account and conversation until it is emptied', () => {
    setDraft('me@a.test', 'direct:bob@a.test', { text: 'half a thought', picks: [] })
    expect(getDraft('me@a.test', 'direct:bob@a.test')?.text).toBe('half a thought')
    expect(getDraft('you@a.test', 'direct:bob@a.test')).toBeUndefined()
    expect(window.localStorage.getItem('kutup.chat.drafts.v1:me@a.test')).toContain('half a thought')
    setDraft('me@a.test', 'direct:bob@a.test', { text: '   ', picks: [] })
    expect(getDraft('me@a.test', 'direct:bob@a.test')).toBeUndefined()
  })

  it('forgets everything of an account on sign-out', () => {
    setDraft('me@a.test', 'group:g1', { text: 'plan', picks: [] })
    clearDrafts('me@a.test')
    expect(getDraft('me@a.test', 'group:g1')).toBeUndefined()
    expect(window.localStorage.getItem('kutup.chat.drafts.v1:me@a.test')).toBeNull()
  })
})
