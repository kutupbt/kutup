import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import './testI18n'
import type { ParsedMessage } from '@kutup/mail-core/mime'

const addImageSender = vi.fn()
let remoteImages: 'ask' | 'always' = 'ask'
let senders: { address: string }[] = []
let imageProxy = true
let embeddedImages = true
const fetchMailImage = vi.fn((url: string) =>
  Promise.resolve(url.includes('broken') ? { kind: 'failed' as const } : { kind: 'image' as const, blob: new Blob(['GIF89a'], { type: 'image/gif' }) }),
)
vi.mock('@kutup/mail-core/api', () => ({
  useMailSettings: () => ({ data: { confirmLink: true, remoteImages, imageProxy, embeddedImages } }),
  useImageSenders: () => ({ data: senders }),
  // Outside senders are kept lowercased (this server's folded).
  useSenderKey: (address: string | undefined) => ({ data: address?.trim().toLowerCase() }),
  useAddImageSender: () => ({ mutate: addImageSender }),
  fetchMailImage: (url: string) => fetchMailImage(url),
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
  fetchMailImage.mockClear()
  remoteImages = 'ask'
  senders = []
  imageProxy = true
  embeddedImages = true
})

const frameDoc = () => screen.getByTitle('Message').getAttribute('srcdoc') ?? ''

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

describe('tracker protection', () => {
  const newsletter = {
    html:
      '<p>Haber</p><img src="https://cdn.example.org/logo.png"><img src="https://x.us1.list-manage.com/track/open.php?u=1">' +
      '<img src="https://broken.example.org/a.png"><a href="https://shop.example/item?id=7&amp;utm_source=news&amp;fbclid=x">Shop</a>',
    text: null,
    attachments: [],
  } as unknown as ParsedMessage

  it('counts trackers and cleaned links before anything loads', async () => {
    render(<MailBody parsed={newsletter} sender="news@example.org" />)
    expect(await screen.findByRole('button', { name: '1 tracker blocked · 1 link cleaned' })).toBeTruthy()
    expect(fetchMailImage).not.toHaveBeenCalled()
    expect(frameDoc()).toContain('href="https://shop.example/item?id=7"')
    fireEvent.click(screen.getByRole('button', { name: '1 tracker blocked · 1 link cleaned' }))
    const dialog = screen.getByRole('dialog', { name: 'Email tracker protection' })
    expect(within(within(dialog).getByRole('list', { name: 'Blocked trackers' })).getByText('Mailchimp')).toBeTruthy()
    expect(within(dialog).getByText('Removed: utm_source, fbclid')).toBeTruthy()
  })

  it('loads images through the proxy, never the tracker, and the rest directly only when asked', async () => {
    remoteImages = 'always'
    render(<MailBody parsed={newsletter} sender="news@example.org" />)
    await waitFor(() => expect(frameDoc()).toContain('src="blob:'))
    const doc = frameDoc()
    expect(doc).not.toContain('cdn.example.org')
    expect(doc).not.toContain('list-manage')
    expect(fetchMailImage).not.toHaveBeenCalledWith(expect.stringContaining('list-manage'))
    // Only proxied images in the frame: its policy allows no remote loads.
    expect(doc).toContain("img-src data: blob:;")
    fireEvent.click(await screen.findByRole('button', { name: 'Load' }))
    await waitFor(() => expect(frameDoc()).toContain('src="https://broken.example.org/a.png"'))
    expect(frameDoc()).not.toContain('list-manage')
  })

  it('loads directly and leaves links alone when turned off', () => {
    remoteImages = 'always'
    imageProxy = false
    render(<MailBody parsed={newsletter} sender="news@example.org" />)
    const doc = frameDoc()
    expect(doc).toContain('src="https://cdn.example.org/logo.png"')
    expect(doc).toContain('utm_source=news')
    expect(screen.queryByRole('button', { name: /tracker/ })).toBeNull()
    expect(fetchMailImage).not.toHaveBeenCalled()
  })
})

describe('embedded images', () => {
  const withLogo = {
    html: '<p>Merhaba</p><img src="cid:logo@x" alt="logo">',
    text: null,
    attachments: [{ contentId: 'logo@x', mimeType: 'image/png', content: new Uint8Array([137, 80, 78, 71]) }],
  } as unknown as ParsedMessage

  it('show at once unless turned off, then wait to be loaded', () => {
    const shown = render(<MailBody parsed={withLogo} sender="a@example.org" />)
    expect(frameDoc()).toContain('src="blob:')
    expect(screen.queryByText('This message contains embedded images.')).toBeNull()
    shown.unmount()
    embeddedImages = false
    render(<MailBody parsed={withLogo} sender="a@example.org" />)
    expect(frameDoc()).not.toContain('src="blob:')
    fireEvent.click(screen.getByRole('button', { name: 'Load embedded images' }))
    expect(frameDoc()).toContain('src="blob:')
    expect(screen.queryByText('This message contains embedded images.')).toBeNull()
  })
})
