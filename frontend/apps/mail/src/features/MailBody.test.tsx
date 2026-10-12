import { fireEvent, render, screen, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import './testI18n'
import type { ParsedMessage } from '@kutup/mail-core/mime'

const addImageSender = vi.fn()
let remoteImages: 'ask' | 'always' = 'ask'
let senders: { address: string }[] = []
vi.mock('@kutup/mail-core/api', () => ({
  useMailSettings: () => ({ data: { confirmLink: true, remoteImages } }),
  useImageSenders: () => ({ data: senders }),
  useAddImageSender: () => ({ mutate: addImageSender }),
}))
vi.mock('next-themes', () => ({ useTheme: () => ({ resolvedTheme: 'light' }) }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

// jsdom has no ResizeObserver; the frame's sizing is not what is tested here.
globalThis.ResizeObserver ??= class {
  observe() {}
  disconnect() {}
  unobserve() {}
} as unknown as typeof ResizeObserver

const { MailBody } = await import('./MailBody')

const parsed = { html: '<p>Haber</p><img src="https://tracker.example/p.png">', text: null, attachments: [] } as unknown as ParsedMessage
const banner = () => screen.queryByText('Remote images are blocked to protect your privacy.')

beforeEach(() => {
  addImageSender.mockClear()
  remoteImages = 'ask'
  senders = []
})

describe('remote images', () => {
  it('asks before loading, and can remember the sender', () => {
    render(<MailBody parsed={parsed} sender="News@Example.org" />)
    expect(banner()).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Load images' }))
    const dialog = screen.getByRole('dialog', { name: 'Load remote images?' })
    fireEvent.click(within(dialog).getByRole('checkbox', { name: 'Always load images from News@Example.org' }))
    fireEvent.click(within(dialog).getByRole('button', { name: 'Load images' }))
    expect(addImageSender).toHaveBeenCalledWith('News@Example.org', expect.anything())
    expect(banner()).toBeNull()
  })

  it('loads once without remembering, and Cancel loads nothing', () => {
    render(<MailBody parsed={parsed} sender="news@example.org" />)
    fireEvent.click(screen.getByRole('button', { name: 'Load images' }))
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Cancel' }))
    expect(banner()).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Load images' }))
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Load images' }))
    expect(addImageSender).not.toHaveBeenCalled()
    expect(banner()).toBeNull()
  })

  it('loads at once for a remembered sender or the setting, never in Spam', () => {
    senders = [{ address: 'news@example.org' }]
    const { unmount } = render(<MailBody parsed={parsed} sender="News@example.org" />)
    expect(banner()).toBeNull()
    unmount()
    const spam = render(<MailBody parsed={parsed} sender="news@example.org" suspicious />)
    expect(banner()).toBeTruthy()
    // In Spam there is no "always".
    fireEvent.click(screen.getByRole('button', { name: 'Load images' }))
    expect(within(screen.getByRole('dialog')).queryByRole('checkbox')).toBeNull()
    spam.unmount()
    senders = []
    remoteImages = 'always'
    render(<MailBody parsed={parsed} sender="other@example.org" />)
    expect(banner()).toBeNull()
  })
})
