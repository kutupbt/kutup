import { act, fireEvent, render, renderHook, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import './testI18n'

const mutateAsync = vi.fn(() => Promise.resolve(1))
const updateSettings = vi.fn()
const quiet = vi.fn(() => Promise.resolve({ done: 1, manual: 0, failed: 0 }))
let spamAction = 'ask'
vi.mock('@kutup/mail-core/api', () => ({
  membersOf: (rows: { id: string; folder: string; direction: string; customFolder?: string | null }[]) => rows.map(({ id, folder, direction, customFolder }) => ({ id, folder, direction, customFolder: customFolder ?? null })),
  useUpdateMessages: () => ({ mutateAsync, isPending: false }),
  useMailSettings: () => ({ data: { spamAction } }),
  useUpdateMailSettings: () => ({ mutate: updateSettings }),
}))
vi.mock('./spamUnsubscribe', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./spamUnsubscribe')>()),
  useQuietUnsubscribe: () => quiet,
}))
vi.mock('sonner', () => ({ toast: Object.assign(vi.fn(), { success: vi.fn(), error: vi.fn(), info: vi.fn() }) }))

const { useMailActions } = await import('./mailActions')
const { SpamUnsubscribeDialog } = await import('./SpamUnsubscribeDialog')
const { fromList } = await import('./spamUnsubscribe')

const list = { id: 'm1', threadId: 't1', folder: 'inbox' as const, direction: 'inbound' as const, unsubscribable: true, subject: 'Bülten' }
const plain = { id: 'm2', threadId: 't2', folder: 'inbox' as const, direction: 'inbound' as const, unsubscribable: false }

beforeEach(() => {
  mutateAsync.mockClear()
  updateSettings.mockClear()
  quiet.mockClear()
})

describe('moving list mail to Spam (Proton’s SpamAction)', () => {
  it('knows list mail, in a conversation too', () => {
    expect(fromList(list)).toBe(true)
    expect(fromList(plain)).toBe(false)
    expect(fromList({ ...plain, conversation: { members: [{ id: 'x', unsubscribable: true }] } })).toBe(true)
    expect(fromList({ ...list, direction: 'outbound' })).toBe(false)
  })

  it('asks, then moves and unsubscribes, remembering the choice', async () => {
    spamAction = 'ask'
    render(<SpamUnsubscribeDialog />)
    const { result } = renderHook(() => useMailActions())
    act(() => result.current.move([list], 'spam'))
    expect(mutateAsync).not.toHaveBeenCalled()
    expect(await screen.findByText(/This message will be marked as spam/)).toBeTruthy()
    fireEvent.click(screen.getByRole('checkbox', { name: 'Remember my choice' }))
    fireEvent.click(screen.getByRole('button', { name: 'Move to spam and unsubscribe' }))
    expect(updateSettings).toHaveBeenCalledWith({ spamAction: 'spam_and_unsubscribe' })
    expect(mutateAsync).toHaveBeenCalledWith(expect.objectContaining({ ids: ['m1'], folder: 'spam' }))
    expect(quiet).toHaveBeenCalledWith([list])
  })

  it('moves without asking when the choice is set, and never asks for other mail', () => {
    spamAction = 'just_spam'
    const { result, rerender } = renderHook(() => useMailActions())
    act(() => result.current.move([list], 'spam'))
    expect(mutateAsync).toHaveBeenCalledTimes(1)
    expect(quiet).not.toHaveBeenCalled()
    spamAction = 'spam_and_unsubscribe'
    rerender()
    act(() => result.current.move([list], 'spam'))
    expect(quiet).toHaveBeenCalledWith([list])
    spamAction = 'ask'
    rerender()
    act(() => result.current.move([plain], 'spam'))
    expect(mutateAsync).toHaveBeenCalledTimes(3)
  })
})
