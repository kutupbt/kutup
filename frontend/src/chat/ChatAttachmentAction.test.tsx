import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import type { ChatAttachmentDescriptorV1 } from './types'
import { ChatAttachmentAction } from './ChatAttachmentAction'

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
  filename: 'report.pdf',
  mimeType: 'application/pdf',
  mediaClass: 'file',
}

describe('ChatAttachmentAction', () => {
  it('downloads without opening while the attachment is remote', async () => {
    const onDownload = vi.fn().mockResolvedValue(undefined)
    const onOpen = vi.fn()
    render(<ChatAttachmentAction
      attachment={attachment}
      cacheState="remote"
      downloadProgress={0}
      viewerKind="pdf"
      onDownload={onDownload}
      onCancel={() => {}}
      onOpen={onOpen}
      onError={() => {}}
    />)

    fireEvent.click(screen.getByRole('button', { name: 'Download report.pdf into Kutup' }))
    await waitFor(() => expect(onDownload).toHaveBeenCalledOnce())
    expect(onOpen).not.toHaveBeenCalled()
  })

  it('shows progress and cancels from the same circular control', () => {
    const onCancel = vi.fn()
    render(<ChatAttachmentAction
      attachment={attachment}
      cacheState="downloading"
      downloadProgress={42}
      viewerKind="pdf"
      onDownload={async () => {}}
      onCancel={onCancel}
      onOpen={() => {}}
      onError={() => {}}
    />)

    expect(screen.getByTestId('chat-attachment-download-progress')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Cancel download of report.pdf' }))
    expect(onCancel).toHaveBeenCalledOnce()
  })

  it('opens only after the verified local copy is available', () => {
    const onOpen = vi.fn()
    render(<ChatAttachmentAction
      attachment={attachment}
      cacheState="available"
      downloadProgress={100}
      viewerKind="pdf"
      onDownload={async () => {}}
      onCancel={() => {}}
      onOpen={onOpen}
      onError={() => {}}
    />)

    fireEvent.click(screen.getByRole('button', { name: 'Open report.pdf' }))
    expect(onOpen).toHaveBeenCalledOnce()
  })
})
