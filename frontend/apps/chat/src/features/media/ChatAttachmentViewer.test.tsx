import { render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import './testI18n'
import type { PrivateCiphertextCacheV1 } from '@kutup/files/mediaCache'
import type { ChatAttachmentDescriptorV1 } from '@kutup/chat-core/types'

const { openCachedChatMediaV1, openChatMediaPlaybackV1 } = vi.hoisted(() => ({
  openCachedChatMediaV1: vi.fn(),
  openChatMediaPlaybackV1: vi.fn(),
}))
vi.mock('@kutup/chat-core/media', () => ({
  openCachedChatMediaV1,
  openChatMediaPlaybackV1,
  chatMediaViewerKindV1: ({ mimeType }: { mimeType: string }) =>
    mimeType.startsWith('video/') ? 'video' : mimeType.startsWith('audio/') ? 'audio' : mimeType.startsWith('image/') ? 'image' : 'pdf',
}))

import { ChatAttachmentViewer } from './ChatAttachmentViewer'

const attachment: ChatAttachmentDescriptorV1 = {
  version: 1,
  suite: 2,
  attachmentId: '11111111-1111-4111-8111-111111111111',
  originDomain: 'a.test',
  retrievalToken: 'opaque',
  ciphertextBytes: 100,
  ciphertextSha256: 'ab'.repeat(32),
  manifestSha256: 'MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM=',
  attachmentKey: 'opaque-key',
  plaintextBytes: 24,
  filename: 'photo.png',
  mimeType: 'image/png',
  mediaClass: 'photo',
}
const cache = {} as PrivateCiphertextCacheV1
const revokeObjectURL = vi.fn()

describe('Chat attachment viewer', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    Object.defineProperty(URL, 'createObjectURL', {
      configurable: true,
      value: vi.fn(() => 'blob:verified-chat-media'),
    })
    Object.defineProperty(URL, 'revokeObjectURL', {
      configurable: true,
      value: revokeObjectURL,
    })
  })

  it('mounts verified media and revokes the transient URL on close', async () => {
    openCachedChatMediaV1.mockResolvedValue({
      blob: new Blob([new Uint8Array([1])], { type: 'image/png' }),
      mimeType: 'image/png',
      kind: 'image',
    })
    const view = render(
      <ChatAttachmentViewer
        open
        onOpenChange={() => {}}
        cache={cache}
        attachment={attachment}
      />,
    )
    expect(await screen.findByRole('img', { name: 'photo.png' }))
      .toHaveAttribute('src', 'blob:verified-chat-media')
    view.rerender(
      <ChatAttachmentViewer
        open={false}
        onOpenChange={() => {}}
        cache={cache}
        attachment={attachment}
      />,
    )
    await waitFor(() => expect(revokeObjectURL).toHaveBeenCalledWith('blob:verified-chat-media'))
  })

  it('shows a safe error state when local verification or classification fails', async () => {
    openCachedChatMediaV1.mockRejectedValue(new Error('attachment type is not safe'))
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    render(
      <ChatAttachmentViewer
        open
        onOpenChange={() => {}}
        cache={cache}
        attachment={attachment}
      />,
    )
    // The protocol's reason goes to the console; people see translated copy.
    expect(await screen.findByText('This attachment could not be opened safely.')).toBeInTheDocument()
    expect(screen.queryByText('attachment type is not safe')).not.toBeInTheDocument()
    expect(warn).toHaveBeenCalled()
    expect(screen.queryByRole('img', { name: 'photo.png' })).not.toBeInTheDocument()
  })

  it('opens a verified PDF inside the app', async () => {
    openCachedChatMediaV1.mockResolvedValue({
      blob: new Blob([new TextEncoder().encode('%PDF-1.7')], { type: 'application/pdf' }),
      mimeType: 'application/pdf',
      kind: 'pdf',
    })
    render(
      <ChatAttachmentViewer
        open
        onOpenChange={() => {}}
        cache={cache}
        attachment={{
          ...attachment,
          filename: 'report.pdf',
          mimeType: 'application/pdf',
          mediaClass: 'file',
        }}
      />,
    )

    expect(await screen.findByTitle('report.pdf')).toHaveAttribute('src', 'blob:verified-chat-media')
  })

  it('streams a video through the service worker and closes the stream with the viewer', async () => {
    const close = vi.fn()
    openChatMediaPlaybackV1.mockResolvedValue({ kind: 'ready', src: '/sw/stream/abc', streamed: true, close })
    const video = { ...attachment, filename: 'clip.webm', mimeType: 'video/webm', mediaClass: 'video' as const }
    const view = render(<ChatAttachmentViewer open onOpenChange={() => {}} cache={cache} attachment={video} />)
    await waitFor(() => expect(document.querySelector('video')).toHaveAttribute('src', '/sw/stream/abc'))
    expect(openCachedChatMediaV1).not.toHaveBeenCalled()
    view.rerender(<ChatAttachmentViewer open={false} onOpenChange={() => {}} cache={cache} attachment={video} />)
    await waitFor(() => expect(close).toHaveBeenCalled())
  })

  it('says so when the tab plays too many streams', async () => {
    openChatMediaPlaybackV1.mockResolvedValue({ kind: 'busy' })
    render(<ChatAttachmentViewer open onOpenChange={() => {}} cache={cache} attachment={{ ...attachment, filename: 'song.mp3', mimeType: 'audio/mpeg' }} />)
    expect(await screen.findByText('Too many videos or songs are playing in this tab. Close one to play this.')).toBeInTheDocument()
  })
})
