import { afterEach, describe, expect, it, vi } from 'vitest'

const serverAddressOf = vi.fn<(account: { accountId: string }, fresh: boolean) => Promise<string | null>>()
const followAccountRenames = vi.fn<(me: unknown, account: { accountId: string }, current: string, pending?: unknown) => Promise<unknown[]>>()
const forgetAccountName = vi.fn<(key: string) => void>()
vi.mock('@kutup/drive-core/accountName', () => ({ serverAddressOf: (...a: Parameters<typeof serverAddressOf>) => serverAddressOf(...a) }))
vi.mock('@kutup/drive-core/identityPins', () => ({ followAccountRenames: (...a: Parameters<typeof followAccountRenames>) => followAccountRenames(...a) }))
vi.mock('./accountNames', () => ({
  driveIdentity: () => Promise.resolve({ account: 'me@a.test' }),
  forgetAccountName: (key: string) => forgetAccountName(key),
}))

const { checkRenames, renameSuspected, resetRenameWatch } = await import('./renameWatch')
const { directPeersByRecency } = await import('../app/chatStore')

const key = (n: number) => `aci:00000000-0000-4000-8000-00000000000${n}@a.test`
const RENAME = { from: 'ada@a.test', to: 'ada.new@a.test', sequence: 1, issuedAtMs: 1 }

const record = vi.fn<(account: unknown, rename: unknown) => Promise<boolean>>()
const pendingPin = vi.fn<(account: unknown) => Promise<unknown>>()

function service(written = true, pending: unknown = null) {
  record.mockReset()
  record.mockResolvedValue(written)
  pendingPin.mockReset()
  pendingPin.mockResolvedValue(pending)
  return { recordPeerRenamed: record, pendingIdentityPin: pendingPin } as unknown as import('@kutup/chat-core/service').ChatService
}

afterEach(() => {
  resetRenameWatch()
  serverAddressOf.mockReset()
  followAccountRenames.mockReset()
  forgetAccountName.mockReset()
})

describe('checkRenames', () => {
  it('follows a few due peers a pass, newest first, and writes each new rename once', async () => {
    serverAddressOf.mockResolvedValue('ada.new@a.test')
    followAccountRenames.mockImplementation((_me, account) =>
      Promise.resolve(account.accountId.endsWith('1') ? [RENAME] : []))
    const chat = service()
    const changed = vi.fn()
    const peers = [1, 2, 3, 4, 5].map(key)
    await checkRenames(chat, peers, changed, 1_000_000)
    expect(followAccountRenames).toHaveBeenCalledTimes(3)
    expect(followAccountRenames.mock.calls.map(([, account]) => account.accountId.at(-1))).toEqual(['1', '2', '3'])
    // Asked fresh, the server's label now, never a cached one.
    expect(serverAddressOf).toHaveBeenCalledWith(expect.anything(), true)
    expect(record).toHaveBeenCalledWith({ server: 'a.test', accountId: '00000000-0000-4000-8000-000000000001' }, RENAME)
    expect(forgetAccountName).toHaveBeenCalledWith(key(1))
    expect(changed).toHaveBeenCalledOnce()
    // The next pass takes the rest; the ones asked wait their turn.
    await checkRenames(chat, peers, changed, 1_000_001)
    expect(followAccountRenames.mock.calls.slice(3).map(([, account]) => account.accountId.at(-1))).toEqual(['4', '5'])
    await checkRenames(chat, peers, changed, 1_000_002)
    expect(followAccountRenames).toHaveBeenCalledTimes(5)
    // Five minutes later they are due again.
    await checkRenames(chat, peers, changed, 1_000_000 + 5 * 60_000)
    expect(followAccountRenames).toHaveBeenCalledTimes(8)
  })

  it('asks at once about a peer whose label changed, and again after a failure', async () => {
    serverAddressOf.mockResolvedValue('ada@a.test')
    followAccountRenames.mockResolvedValue([])
    const chat = service()
    await checkRenames(chat, [key(1)], () => {}, 10)
    renameSuspected(key(1))
    await checkRenames(chat, [key(1)], () => {}, 11)
    expect(followAccountRenames).toHaveBeenCalledTimes(2)
    followAccountRenames.mockRejectedValueOnce(new Error('offline'))
    renameSuspected(key(1))
    await checkRenames(chat, [key(1)], () => {}, 12)
    await checkRenames(chat, [key(1)], () => {}, 13)
    expect(followAccountRenames).toHaveBeenCalledTimes(4)
  })

  it('says nothing new when the line was there already', async () => {
    serverAddressOf.mockResolvedValue('ada.new@a.test')
    followAccountRenames.mockResolvedValue([RENAME])
    const changed = vi.fn()
    await checkRenames(service(false), [key(1)], changed, 10)
    expect(changed).not.toHaveBeenCalled()
  })
})

describe('directPeersByRecency', () => {
  it('lists direct peers newest first, requests too, without Note to Self or groups', () => {
    const direct = (n: number) => ({ kind: 'direct' as const, account: { server: 'a.test', accountId: `00000000-0000-4000-8000-00000000000${n}` } })
    const history = [
      { conversation: direct(1), timestampMs: 10 },
      { conversation: direct(2), timestampMs: 30 },
      { conversation: direct(9), timestampMs: 50 },
      { conversation: { kind: 'group' as const, groupId: 'g' }, timestampMs: 60 },
      { conversation: direct(1), timestampMs: 40 },
    ]
    const contacts = [{ peer: key(3), updatedAtMs: 20 }, { peer: key(1), updatedAtMs: 1 }]
    expect(directPeersByRecency(history, contacts, key(9))).toEqual([key(1), key(2), key(3)])
  })

  it("follows a peer met lately against Chat's pin that isn't written yet", async () => {
    serverAddressOf.mockResolvedValue('ada.new@a.test')
    followAccountRenames.mockResolvedValue([RENAME])
    const pending = { authorityPublicKey: 'A', since: '2026-10-20T00:00:00Z' }
    await checkRenames(service(true, pending), [key(1)], vi.fn(), 10)
    expect(followAccountRenames.mock.calls[0]?.[3]).toEqual(pending)
    expect(record).toHaveBeenCalledWith(expect.anything(), RENAME)
  })
})
