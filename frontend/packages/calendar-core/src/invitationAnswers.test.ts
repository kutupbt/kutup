import { describe, expect, it, vi } from 'vitest'

// Security review M1: every attendee holds the shared key and can seal an
// answer for another attendee's row; a row must verify only against the
// organizer's keys and that row's own attendee's.

vi.mock('@kutup/crypto/calendar', () => ({ openInvitation: vi.fn() }))
vi.mock('@kutup/session/client', () => ({ default: {} }))
vi.mock('@kutup/session/apps', () => ({ loadServerSettings: vi.fn() }))
vi.mock('@kutup/mail-core/keys', () => ({
  addressKeys: (email: string) => Promise.resolve({ all: [`key-of-${email}`] }),
}))
vi.mock('./api', () => ({
  activeAddressId: vi.fn(),
  authorKeys: (_account: unknown, organizer: string) => Promise.resolve([`key-of-${organizer}`]),
  beforeEventWrite: vi.fn(),
  syncOne: vi.fn(),
  timesOf: vi.fn(),
}))

const { openAnswerRows } = await import('./invitations')

const account = { isOwnAddress: (a: string) => a === 'ali@kutup.test', ownPublicKeys: ['key-of-ali'] }

describe('answer rows', () => {
  it("open each row only with the organizer's keys and its own attendee's", async () => {
    const seen: Record<string, string[]> = {}
    const open = (rows: { token: string; answer: string | null }[], keys: string[]) => {
      seen[rows[0].token] = keys
      return [{ token: rows[0].token, answer: null, verified: false }]
    }
    await openAnswerRows(
      account as never,
      open,
      'org@kutup.test',
      [
        { email: 'bob@kutup.test', token: 't-bob' },
        { email: 'mallory@kutup.test', token: 't-mallory' },
        { email: 'ali@kutup.test', token: 't-ali' },
      ],
      [
        { token: 't-bob', answer: 'sealed' },
        { token: 't-mallory', answer: 'sealed' },
        { token: 't-ali', answer: 'sealed' },
        { token: 't-unknown', answer: 'sealed' },
      ],
    )
    expect(seen['t-bob']).toEqual(['key-of-org@kutup.test', 'key-of-bob@kutup.test'])
    expect(seen['t-mallory']).toEqual(['key-of-org@kutup.test', 'key-of-mallory@kutup.test'])
    expect(seen['t-ali']).toEqual(['key-of-org@kutup.test', 'key-of-ali'])
    // A row no listed attendee's token names: only the organizer may have signed it.
    expect(seen['t-unknown']).toEqual(['key-of-org@kutup.test'])
  })
})
