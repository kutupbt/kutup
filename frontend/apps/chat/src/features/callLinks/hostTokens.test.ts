import { beforeEach, describe, expect, it, vi } from 'vitest'

const refresh = vi.fn<() => Promise<{ accessToken: string; sessionId: string }>>()
const persisted = vi.fn<() => { v: 1; sessionId: string; userId: string; blob: string } | null>()
vi.mock('@kutup/session/client', () => ({ refreshAccessToken: () => refresh() }))
vi.mock('@kutup/session/persistedStore', () => ({ readPersisted: () => persisted() }))

const { forgetAccountHostTokens, hostTokenFor, rememberHostToken, verifiedHostAccount } = await import('./hostTokens')

const ROOM = 'a'.repeat(32)

describe('meeting host tokens', () => {
  beforeEach(() => {
    localStorage.clear()
    refresh.mockReset()
    persisted.mockReset()
  })

  it('belong to the account that stored them, and go when it signs out', () => {
    rememberHostToken('alice', ROOM, 'token-a')
    expect(hostTokenFor('alice', ROOM)).toBe('token-a')
    expect(hostTokenFor('bob', ROOM)).toBeNull()
    forgetAccountHostTokens('alice')
    expect(hostTokenFor('alice', ROOM)).toBeNull()
    expect(localStorage.getItem('kutup-meeting-hosts')).toBeNull()
  })

  it('drop the old map that no account owned', () => {
    localStorage.setItem('kutup-meeting-hosts', JSON.stringify({ [ROOM]: 'token-old' }))
    expect(hostTokenFor('alice', ROOM)).toBeNull()
  })

  it('are used only for a sign-in the server confirms is still live', async () => {
    persisted.mockReturnValue(null)
    expect(await verifiedHostAccount()).toBeNull()
    expect(refresh).not.toHaveBeenCalled()

    persisted.mockReturnValue({ v: 1, sessionId: 's1', userId: 'alice', blob: 'x' })
    refresh.mockResolvedValue({ accessToken: 't', sessionId: 's1' })
    expect(await verifiedHostAccount()).toBe('alice')

    // Signed out elsewhere: the stored session is left behind, the server says no.
    refresh.mockRejectedValue(new Error('401'))
    expect(await verifiedHostAccount()).toBeNull()

    // Another sign-in than the one stored here.
    refresh.mockResolvedValue({ accessToken: 't', sessionId: 's2' })
    expect(await verifiedHostAccount()).toBeNull()
  })
})
