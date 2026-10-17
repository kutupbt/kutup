import { afterEach, describe, expect, it, vi } from 'vitest'
import { i18n } from '@kutup/i18n'
import '../features/media/testI18n'

const nameOfAccount = vi.fn<(...args: unknown[]) => unknown>()
vi.mock('@kutup/drive-core/accountName', () => ({ nameOfAccount: (...args: unknown[]) => nameOfAccount(...args) }))
vi.mock('@kutup/drive-core/identity', () => ({ driveIdentityOf: () => Promise.resolve({ account: 'me@a.test' }) }))

const { accountName, distrustAddress, startAccountNames, stopAccountNames } = await import('./accountNames')
const { personName } = await import('../lib/names')
const t = i18n.t.bind(i18n)

const ADA = 'aci:00000000-0000-4000-8000-00000000000a@a.test'
const ME = 'aci:00000000-0000-4000-8000-00000000000e@a.test'
const session = {} as Parameters<typeof startAccountNames>[0]
const settle = () => new Promise((resolve) => setTimeout(resolve, 0))

afterEach(() => {
  stopAccountNames()
  nameOfAccount.mockReset()
})

describe('accountName', () => {
  it('looks an account up once, tells when its name arrives, and never shows a key', async () => {
    nameOfAccount.mockResolvedValue('ada@a.test')
    const changed = vi.fn()
    startAccountNames(session, changed)
    expect(accountName(ADA)).toBeNull()
    expect(accountName(ADA)).toBeNull()
    await settle()
    expect(changed).toHaveBeenCalledOnce()
    expect(accountName(ADA)).toBe('ada@a.test')
    expect(nameOfAccount).toHaveBeenCalledOnce()
    // Not an account key (an address included): nothing is looked up.
    expect(accountName('ada@a.test')).toBeNull()
    expect(nameOfAccount).toHaveBeenCalledOnce()
  })

  it('asks again later: a failure is retried, and a newer (pinned) name replaces the earlier one', async () => {
    nameOfAccount.mockRejectedValueOnce(new Error('offline')).mockResolvedValueOnce('ada.server@a.test').mockResolvedValueOnce('ada@a.test')
    startAccountNames(session, () => {})
    const start = Date.now()
    accountName(ADA, start)
    await settle()
    expect(accountName(ADA, start + 1_000)).toBeNull()
    expect(accountName(ADA, start + 31_000)).toBeNull()
    await settle()
    expect(accountName(ADA, start + 32_000)).toBe('ada.server@a.test')
    expect(accountName(ADA, Date.now() + 6 * 60_000)).toBe('ada.server@a.test')
    await settle()
    expect(accountName(ADA)).toBe('ada@a.test')
  })

  it('never names an account by an address that belongs to someone else the user knows', async () => {
    nameOfAccount.mockResolvedValue('ada@a.test')
    startAccountNames(session, () => {})
    distrustAddress({ server: 'a.test', accountId: '00000000-0000-4000-8000-00000000000a' }, 'Ada@a.test')
    accountName(ADA)
    await settle()
    expect(accountName(ADA)).toBeNull()
  })
})

describe('personName', () => {
  it('is "You", the profile name, the account’s address, else "Someone": never the key', async () => {
    nameOfAccount.mockResolvedValue(null)
    startAccountNames(session, () => {})
    const profiles = new Map([[ADA, { displayName: 'Ada L.' }]])
    expect(personName(ME, profiles, ME, t)).toBe('You')
    expect(personName(ADA, profiles, ME, t)).toBe('Ada L.')
    expect(personName(ADA, new Map(), ME, t)).toBe('Someone')
    await settle()
    expect(personName(ADA, new Map(), ME, t)).toBe('Someone')
  })
})
