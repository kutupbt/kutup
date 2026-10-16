import { beforeEach, describe, expect, it, vi } from 'vitest'
import { i18n } from '@kutup/i18n'
import '../features/media/testI18n'

const lookupAddress = vi.fn<(...args: unknown[]) => unknown>()
const checkAnswer = vi.fn<(...args: unknown[]) => unknown>()
class RecipientRenamed extends Error {
  constructor(readonly account: string, readonly now: string) {
    super('renamed')
  }
}
vi.mock('@kutup/drive-core/identityPins', () => ({
  lookupAddress: (...args: unknown[]) => lookupAddress(...args),
  checkAnswer: (...args: unknown[]) => checkAnswer(...args),
  RecipientRenamed,
}))
const distrustAddress = vi.fn<(...args: unknown[]) => unknown>()
vi.mock('../state/accountNames', () => ({
  driveIdentity: () => Promise.resolve({ account: 'me@a.test' }),
  distrustAddress: (...args: unknown[]) => distrustAddress(...args),
}))

const { resolveAddress, resolveTyped } = await import('./resolveAddress')
const t = i18n.t.bind(i18n)

const ADA = { server: 'a.test', accountId: '00000000-0000-4000-8000-00000000000a' }
const MAL = { server: 'a.test', accountId: '00000000-0000-4000-8000-0000000000ff' }

function answer(account: typeof ADA, label: string) {
  return { ...account, username: label.split('@')[0], account: label, accountIncarnationId: 'inc' }
}

beforeEach(() => {
  lookupAddress.mockReset()
  checkAnswer.mockReset()
  distrustAddress.mockReset()
})

describe('resolveAddress', () => {
  it('leads to the account the answer names, checked by the address as typed', async () => {
    lookupAddress.mockResolvedValue(answer(ADA, 'ada@a.test'))
    checkAnswer.mockResolvedValue({ kind: 'ok', verified: false })
    await expect(resolveAddress({ username: 'ada', server: 'a.test' })).resolves.toEqual({ kind: 'found', account: ADA })
    expect(checkAnswer).toHaveBeenCalledWith(expect.anything(), 'ada@a.test', expect.objectContaining({ accountId: ADA.accountId }))
  })

  it('tells a known person’s address answered with someone else, whatever its label, and never names them by it', async () => {
    // The server answers ada@ with Mal's account, labelled as Mal.
    lookupAddress.mockResolvedValue(answer(MAL, 'mal@a.test'))
    checkAnswer.mockResolvedValue({ kind: 'someoneElse', now: 'ada.new@a.test' })
    const resolved = await resolveAddress({ username: 'ada', server: 'a.test' })
    expect(resolved).toEqual({ kind: 'found', account: MAL, someoneElse: { now: 'ada.new@a.test' } })
    // Checked against the typed address, not the label.
    expect(checkAnswer).toHaveBeenCalledWith(expect.anything(), 'ada@a.test', expect.anything())
    expect(distrustAddress).toHaveBeenCalledWith(MAL, 'ada@a.test')
  })

  it('says not found, renamed, and failed (an account on another server than its address)', async () => {
    lookupAddress.mockResolvedValueOnce(null)
    await expect(resolveAddress({ username: 'ada', server: 'a.test' })).resolves.toEqual({ kind: 'notFound' })
    lookupAddress.mockRejectedValueOnce(new RecipientRenamed('ada@a.test', 'ada2@a.test'))
    await expect(resolveAddress({ username: 'ada', server: 'a.test' })).resolves.toEqual({ kind: 'renamed', now: 'ada2@a.test' })
    lookupAddress.mockResolvedValueOnce(answer({ ...ADA, server: 'b.test' }, 'ada@b.test'))
    await expect(resolveAddress({ username: 'ada', server: 'a.test' })).resolves.toEqual({ kind: 'failed' })
    lookupAddress.mockRejectedValueOnce(new Error('offline'))
    await expect(resolveAddress({ username: 'ada', server: 'a.test' })).resolves.toEqual({ kind: 'failed' })
  })
})

describe('resolveTyped', () => {
  it('reads a bare username on the home server and words every outcome', async () => {
    lookupAddress.mockResolvedValue(answer(ADA, 'ada@a.test'))
    checkAnswer.mockResolvedValue({ kind: 'ok', verified: false })
    await expect(resolveTyped('ada', 'a.test', t)).resolves.toEqual({ account: ADA })
    expect(lookupAddress).toHaveBeenCalledWith(expect.anything(), 'ada@a.test')
    await expect(resolveTyped('a', 'a.test', t)).resolves.toEqual({ error: t('chat.errors.invalidAddress') })
    lookupAddress.mockResolvedValueOnce(null)
    await expect(resolveTyped('nobody@a.test', 'a.test', t)).resolves.toEqual({ error: 'No Kutup account has this address.' })
  })

  it('opens someone else at a known person’s address only with the notice', async () => {
    lookupAddress.mockResolvedValue(answer(MAL, 'ada@a.test'))
    checkAnswer.mockResolvedValue({ kind: 'someoneElse', name: 'mal@a.test' })
    const resolved = await resolveTyped('ada@a.test', 'a.test', t)
    expect(resolved).toMatchObject({ account: MAL })
    expect((resolved as { warning: string }).warning).toBe(
      'The person you knew at ada@a.test no longer has this address. Whoever has it now is someone else: check who they are before you trust anything from them. It is the account you know as mal@a.test.',
    )
  })
})
