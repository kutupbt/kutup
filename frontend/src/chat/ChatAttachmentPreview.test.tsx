import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { CHAT_PREVIEW_PROFILE_V1, PREVIEW_WAVEFORM_MIME } from '@/mediaPreview'
import type { ChatAttachmentDescriptorV1 } from './types'
import { encodeChatMediaPreviewV1 } from './media-preview'
import { ChatAttachmentPreview } from './ChatAttachmentPreview'

function descriptor(preview: ChatAttachmentDescriptorV1['preview']): ChatAttachmentDescriptorV1 {
  return {
    version: 1,
    suite: 1,
    attachmentId: '11111111-1111-4111-8111-111111111111',
    originDomain: 'a.test',
    retrievalToken: 'token',
    ciphertextBytes: 100,
    ciphertextSha256: 'ab'.repeat(32),
    attachmentKey: 'key',
    plaintextBytes: 50,
    filename: 'photo.webp',
    mimeType: 'image/webp',
    mediaClass: 'photo',
    preview,
  }
}

function webp(): Uint8Array {
  const bytes = new Uint8Array(20)
  bytes.set(new TextEncoder().encode('RIFF'), 0)
  bytes.set(new TextEncoder().encode('WEBP'), 8)
  return bytes
}

describe('ChatAttachmentPreview', () => {
  it('renders a validated raster and revokes its temporary URL', async () => {
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:preview-test')
    const revoke = vi.spyOn(URL, 'revokeObjectURL')
    const view = render(<ChatAttachmentPreview attachment={descriptor(
      encodeChatMediaPreviewV1({
        kind: 'image',
        contentType: 'image/webp',
        width: 100,
        height: 50,
        raster: webp(),
      }),
    )} />)
    expect(await screen.findByTestId('chat-raster-preview')).toHaveAttribute('src', 'blob:preview-test')
    view.unmount()
    expect(revoke).toHaveBeenCalledWith('blob:preview-test')
  })

  it('makes a raster preview directly activatable', async () => {
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:preview-action')
    const onActivate = vi.fn()
    render(<ChatAttachmentPreview
      attachment={descriptor(encodeChatMediaPreviewV1({
        kind: 'image',
        contentType: 'image/webp',
        width: 100,
        height: 50,
        raster: webp(),
      }))}
      onActivate={onActivate}
      activationLabel="Open photo.webp"
    />)
    fireEvent.click(await screen.findByRole('button', { name: 'Open photo.webp' }))
    expect(onActivate).toHaveBeenCalledOnce()
  })

  it('renders the canonical waveform without a Blob URL', () => {
    const samples = new Uint8Array(CHAT_PREVIEW_PROFILE_V1.waveformSamples).fill(128)
    render(<ChatAttachmentPreview attachment={descriptor(encodeChatMediaPreviewV1({
      kind: 'audio-waveform',
      contentType: PREVIEW_WAVEFORM_MIME,
      durationMs: 1000,
      waveform: samples,
    }))} />)
    const waveform = screen.getByTestId('chat-audio-waveform-preview')
    expect(waveform.children).toHaveLength(CHAT_PREVIEW_PROFILE_V1.waveformSamples)
  })

  it('fills the played portion of an audio waveform', () => {
    const samples = new Uint8Array(CHAT_PREVIEW_PROFILE_V1.waveformSamples).fill(128)
    render(<ChatAttachmentPreview
      attachment={descriptor(encodeChatMediaPreviewV1({
        kind: 'audio-waveform',
        contentType: PREVIEW_WAVEFORM_MIME,
        durationMs: 1000,
        waveform: samples,
      }))}
      progress={0.5}
    />)
    const waveform = screen.getByTestId('chat-audio-waveform-preview')
    expect(waveform.querySelectorAll('.opacity-80')).toHaveLength(CHAT_PREVIEW_PROFILE_V1.waveformSamples / 2)
    expect(waveform.querySelectorAll('.opacity-25')).toHaveLength(CHAT_PREVIEW_PROFILE_V1.waveformSamples / 2)
  })

  it('falls back silently when a hostile preview reaches the UI', async () => {
    const { container } = render(<ChatAttachmentPreview attachment={descriptor({
      mimeType: 'image/webp',
      data: btoa('not-webp'),
    })} />)
    await waitFor(() => expect(container).toBeEmptyDOMElement())
  })

  it('does not decode or render a preview before a message request is accepted', () => {
    const createObjectUrl = vi.spyOn(URL, 'createObjectURL')
    createObjectUrl.mockClear()
    const { container } = render(<ChatAttachmentPreview
      visible={false}
      attachment={descriptor(encodeChatMediaPreviewV1({
        kind: 'image',
        contentType: 'image/webp',
        width: 100,
        height: 50,
        raster: webp(),
      }))}
    />)
    expect(container).toBeEmptyDOMElement()
    expect(createObjectUrl).not.toHaveBeenCalled()
  })
})
