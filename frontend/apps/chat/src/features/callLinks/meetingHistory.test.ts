import { beforeEach, describe, expect, it } from 'vitest'
import { forgetJoinedMeetings, joinedMeetings, recordJoinedMeeting } from './meetingHistory'

const stay = { fragment: 'A'.repeat(44), roomId: 'ab'.repeat(16), title: 'Team sync', joinedAtMs: 1_700_000_000_000, seconds: 90 }

describe('the meetings an account joined from this browser', () => {
  beforeEach(() => localStorage.clear())

  it('ties each stay to the account signed in at the time', () => {
    recordJoinedMeeting(stay, 'user-1')
    recordJoinedMeeting({ ...stay, joinedAtMs: stay.joinedAtMs + 1 }, 'user-2')
    const [second, first] = joinedMeetings()
    expect([first.account, second.account]).toEqual(['user-1', 'user-2'])
    expect(first.id).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(second.id).not.toBe(first.id)
  })

  it('keeps no stay that belongs to no account', () => {
    // As an earlier version stored them: nobody was signed in.
    localStorage.setItem('kutup-meeting-history', JSON.stringify([{ ...stay, id: 'A'.repeat(43) }, { ...stay, id: 'B'.repeat(43), account: '' }]))
    expect(joinedMeetings()).toEqual([])
  })

  it('forgets by id and ignores what is not a stay', () => {
    recordJoinedMeeting(stay, 'user-1')
    const [entry] = joinedMeetings()
    forgetJoinedMeetings(new Set([entry.id]))
    expect(joinedMeetings()).toEqual([])
    localStorage.setItem('kutup-meeting-history', JSON.stringify([{ ...stay, id: 'A'.repeat(43), account: 'user-1', fragment: 'short' }, { ...stay, account: 'user-1' }, 'x', null]))
    expect(joinedMeetings()).toEqual([])
  })
})
