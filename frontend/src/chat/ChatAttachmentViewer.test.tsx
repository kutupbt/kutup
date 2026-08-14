import { render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { PrivateCiphertextCacheV1 } from '@/mediaCache'
import type { ChatAttachmentDescriptorV1 } from './types'

const { openCachedChatMediaV1 } = vi.hoisted(() => ({
  openCachedChatMediaV1: vi.fn(),
}))
vi.mock('./media', () => ({ openCachedChatMediaV1 }))

import { ChatAttachmentViewer } from './ChatAttachmentViewer'

const attachment: ChatAttachmentDescriptorV1 = {
  version: 1,
  suite: 1,
  attachmentId: '11111111-1111-4111-8111-111111111111',
  originDomain: 'a.test',
  retrievalToken: 'opaque',
  ciphertextBytes: 100,
  ciphertextSha256: 'ab'.repeat(32),
  attachmentKey: 'opaque-key',
  plaintextBytes: 24,
  filename: 'photo.png',
  mimeType: 'image/png',
  mediaClass: 'photo',
}
const cache = {} as PrivateCiphertextCacheV1

describe('Chat attachment viewer', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    Object.defineProperty(URL, 'createObjectURL', {
      configurable: true,
      value: vi.fn(() => 'blob:verified-chat-media'),
    })
    Object.defineProperty(URL, 'revokeObjectURL', {
      configurable: true,
      value: vi.fn(),
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
    await waitFor(() => expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:verified-chat-media'))
  })

  it('shows a safe error state when local verification or classification fails', async () => {
    openCachedChatMediaV1.mockRejectedValue(new Error('attachment type is not safe'))
    render(
      <ChatAttachmentViewer
        open
        onOpenChange={() => {}}
        cache={cache}
        attachment={attachment}
      />,
    )
    expect(await screen.findByText('attachment type is not safe')).toBeInTheDocument()
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
})
