import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import './testI18n'
import type { MailAccount, MailMessage } from '@kutup/mail-core/api'

const mutateAsync = vi.fn()
const sendDraft = vi.fn<(...args: unknown[]) => Promise<unknown>>()
vi.mock('@kutup/mail-core/api', () => ({
  useUnsubscribe: () => ({ mutateAsync }),
  usePinnedKeys: () => () => undefined,
  useMailRefresh: () => () => undefined,
  emptyDraft: (_account: unknown, init: object) => ({ to: [], cc: [], bcc: [], subject: '', html: '', text: '', attachments: [], messageId: 'm@kutup.dev', ...init }),
  sendDraft: (...args: unknown[]) => sendDraft(...args),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const { UnsubscribeBanner } = await import('./Unsubscribe')

const account = { address: 'ayse@kutup.dev', domain: 'kutup.dev' } as MailAccount
const message = { id: 'msg-1', direction: 'inbound', unsubscribed: false } as MailMessage
const raw = (headers: string) => new TextEncoder().encode(`From: n@l.example\r\n${headers}\r\n\r\nbody`)

beforeEach(() => {
  mutateAsync.mockReset().mockResolvedValue('msg-1')
  sendDraft.mockReset().mockResolvedValue([])
})

describe('the unsubscribe banner', () => {
  it('sends one click through the server', async () => {
    render(<UnsubscribeBanner account={account} message={message} raw={raw('List-Unsubscribe: <https://l.example/u?id=1>\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click')} />)
    expect(screen.getByText('This message is from a mailing list.')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Unsubscribe' }))
    expect(screen.getByText(/processed automatically/)).toBeTruthy()
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Unsubscribe' }))
    await waitFor(() => expect(mutateAsync).toHaveBeenCalledWith({ id: 'msg-1', oneClickUrl: 'https://l.example/u?id=1' }))
  })

  it('opens a web page, then marks the message', async () => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null)
    render(<UnsubscribeBanner account={account} message={message} raw={raw('List-Unsubscribe: <https://l.example/how>')} />)
    fireEvent.click(screen.getByRole('button', { name: 'Unsubscribe' }))
    expect(screen.getByText('https://l.example/how')).toBeTruthy()
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Unsubscribe' }))
    await waitFor(() => expect(mutateAsync).toHaveBeenCalledWith({ id: 'msg-1' }))
    expect(open).toHaveBeenCalledWith('https://l.example/how', '_blank', 'noopener,noreferrer')
  })

  it('sends the email the list asks for, from the reader', async () => {
    render(<UnsubscribeBanner account={account} message={message} raw={raw('List-Unsubscribe: <mailto:leave@l.example?subject=stop>')} />)
    fireEvent.click(screen.getByRole('button', { name: 'Unsubscribe' }))
    expect(screen.getByText(/sent from ayse@kutup\.dev/)).toBeTruthy()
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Unsubscribe' }))
    await waitFor(() => expect(mutateAsync).toHaveBeenCalledWith({ id: 'msg-1' }))
    const draft = sendDraft.mock.calls[0][1] as { to: { address: string }[]; subject: string }
    expect(draft.to[0].address).toBe('leave@l.example')
    expect(draft.subject).toBe('stop')
  })

  it('says Unsubscribed once done, and shows nothing for other mail', () => {
    const { rerender } = render(<UnsubscribeBanner account={account} message={{ ...message, unsubscribed: true }} raw={raw('List-Unsubscribe: <https://l.example/u>')} />)
    expect(screen.getByRole('button', { name: 'Unsubscribed' })).toHaveProperty('disabled', true)
    rerender(<UnsubscribeBanner account={account} message={message} raw={raw('Subject: hi')} />)
    expect(screen.queryByText('This message is from a mailing list.')).toBeNull()
  })
})
