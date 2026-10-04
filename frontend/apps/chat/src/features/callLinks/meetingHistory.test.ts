import { beforeEach, describe, expect, it } from 'vitest'
import { forgetJoinedMeetings, joinedMeetings, recordJoinedMeeting, setHistoryAccount } from './meetingHistory'

const stay = { fragment: 'A'.repeat(44), roomId: 'ab'.repeat(16), title: 'Team sync', joinedAtMs: 1_700_000_000_000, seconds: 90 }

describe('the meetings joined from this browser', () => {
  beforeEach(() => localStorage.clear())

  it('ties a stay to the account signed in at the time, or to none', () => {
    recordJoinedMeeting(stay)
    setHistoryAccount('user-1')
    recordJoinedMeeting({ ...stay, joinedAtMs: stay.joinedAtMs + 1 })
    setHistoryAccount(null)
    recordJoinedMeeting({ ...stay, joinedAtMs: stay.joinedAtMs + 2 })
    const [third, second, first] = joinedMeetings()
    expect([first.account, second.account, third.account]).toEqual([undefined, 'user-1', undefined])
    expect(new Set([first.id, second.id, third.id]).size).toBe(3)
    expect(first.id).toMatch(/^[0-9a-f]{32}$/)
  })

  it('gives stays recorded before they had ids one that stays the same', () => {
    localStorage.setItem('kutup-meeting-history', JSON.stringify([stay]))
    const [entry] = joinedMeetings()
    expect(entry.id).toMatch(/^[0-9a-f]{32}$/)
    expect(joinedMeetings()[0].id).toBe(entry.id)
  })

  it('forgets by id and ignores what is not a stay', () => {
    recordJoinedMeeting(stay)
    const [entry] = joinedMeetings()
    forgetJoinedMeetings(new Set([entry.id]))
    expect(joinedMeetings()).toEqual([])
    localStorage.setItem('kutup-meeting-history', JSON.stringify([{ ...stay, fragment: 'short' }, 'x', null]))
    expect(joinedMeetings()).toEqual([])
  })
})
