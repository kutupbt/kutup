import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { PrivateCiphertextCacheV1 } from '@/mediaCache'
import { CHAT_PREVIEW_PROFILE_V1, PREVIEW_WAVEFORM_MIME } from '@/mediaPreview'
import { encodeChatMediaPreviewV1 } from './media-preview'
import type { ChatAttachmentDescriptorV1 } from './types'

const { openCachedChatMediaV1 } = vi.hoisted(() => ({
  openCachedChatMediaV1: vi.fn(),
}))
vi.mock('./media', () => ({ openCachedChatMediaV1 }))

import { ChatVoiceNotePlayer } from './ChatVoiceNotePlayer'

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
  filename: 'voice-note.webm',
  mimeType: 'audio/webm',
  mediaClass: 'audio',
  durationMs: 2_000,
}

describe('ChatVoiceNotePlayer', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    Object.defineProperty(URL, 'createObjectURL', {
      configurable: true,
      value: vi.fn(() => 'blob:verified-voice-note'),
    })
    Object.defineProperty(URL, 'revokeObjectURL', {
      configurable: true,
      value: vi.fn(),
    })
    vi.spyOn(HTMLMediaElement.prototype, 'play').mockResolvedValue()
    vi.spyOn(HTMLMediaElement.prototype, 'pause').mockImplementation(() => undefined)
  })

  it('downloads first, then exposes play and opens only on the next action', async () => {
    const onDownload = vi.fn().mockResolvedValue(undefined)
    openCachedChatMediaV1.mockResolvedValue({
      blob: new Blob([new Uint8Array([1])], { type: 'audio/webm' }),
      mimeType: 'audio/webm',
      kind: 'audio',
    })
    const props = {
      cache: {} as PrivateCiphertextCacheV1,
      attachment,
      downloadProgress: 0,
      onDownload,
      onCancel: vi.fn(),
      onError: vi.fn(),
    }
    const view = render(
      <ChatVoiceNotePlayer
        {...props}
        downloadState="remote"
      />,
    )

    fireEvent.click(screen.getByRole('button', { name: 'Download voice-note.webm' }))
    await waitFor(() => expect(onDownload).toHaveBeenCalledOnce())
    expect(openCachedChatMediaV1).not.toHaveBeenCalled()

    view.rerender(<ChatVoiceNotePlayer {...props} downloadState="available" />)
    fireEvent.click(screen.getByRole('button', { name: 'Play voice-note.webm' }))
    await waitFor(() => expect(openCachedChatMediaV1).toHaveBeenCalledOnce())
    const audio = view.container.querySelector('audio')
    expect(audio).not.toBeNull()
    fireEvent.canPlay(audio!)
    expect(HTMLMediaElement.prototype.play).toHaveBeenCalledOnce()
    fireEvent.play(audio!)
    expect(screen.getByRole('button', { name: 'Pause voice-note.webm' })).toBeInTheDocument()
  })

  it('shows circular download progress and cancels from the same control', () => {
    const onCancel = vi.fn()
    render(
      <ChatVoiceNotePlayer
        cache={{} as PrivateCiphertextCacheV1}
        attachment={attachment}
        downloadState="downloading"
        downloadProgress={42}
        onDownload={async () => {}}
        onCancel={onCancel}
        onError={() => {}}
      />,
    )
    expect(screen.getByTestId('voice-note-download-progress')).toBeInTheDocument()
    expect(screen.getByText('42%')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Cancel download of voice-note.webm' }))
    expect(onCancel).toHaveBeenCalledOnce()
  })

  it('cycles through Signal-style playback speeds', () => {
    render(
      <ChatVoiceNotePlayer
        cache={{} as PrivateCiphertextCacheV1}
        attachment={attachment}
        downloadState="available"
        downloadProgress={100}
        onDownload={async () => {}}
        onCancel={() => {}}
        onError={() => {}}
      />,
    )
    const speed = screen.getByRole('button', { name: 'Playback speed 1 times' })
    fireEvent.click(speed)
    expect(screen.getByRole('button', { name: 'Playback speed 1.25 times' })).toHaveTextContent('1.25×')
    fireEvent.click(screen.getByRole('button', { name: 'Playback speed 1.25 times' }))
    expect(screen.getByRole('button', { name: 'Playback speed 1.5 times' })).toHaveTextContent('1.5×')
    fireEvent.click(screen.getByRole('button', { name: 'Playback speed 1.5 times' }))
    expect(screen.getByRole('button', { name: 'Playback speed 2 times' })).toHaveTextContent('2×')
    fireEvent.click(screen.getByRole('button', { name: 'Playback speed 2 times' }))
    expect(screen.getByRole('button', { name: 'Playback speed 1 times' })).toHaveTextContent('1×')
  })

  it('fills the complete waveform when playback ends between time updates', async () => {
    openCachedChatMediaV1.mockResolvedValue({
      blob: new Blob([new Uint8Array([1])], { type: 'audio/webm' }),
      mimeType: 'audio/webm',
      kind: 'audio',
    })
    const voiceNoteWithWaveform = {
      ...attachment,
      preview: encodeChatMediaPreviewV1({
        kind: 'audio-waveform',
        contentType: PREVIEW_WAVEFORM_MIME,
        durationMs: 2_000,
        waveform: new Uint8Array(CHAT_PREVIEW_PROFILE_V1.waveformSamples).fill(128),
      }),
    }
    const view = render(
      <ChatVoiceNotePlayer
        cache={{} as PrivateCiphertextCacheV1}
        attachment={voiceNoteWithWaveform}
        downloadState="available"
        downloadProgress={100}
        onDownload={async () => {}}
        onCancel={() => {}}
        onError={() => {}}
      />,
    )

    fireEvent.click(screen.getByRole('button', { name: 'Play voice-note.webm' }))
    await waitFor(() => expect(openCachedChatMediaV1).toHaveBeenCalledOnce())
    const audio = view.container.querySelector('audio')!
    Object.defineProperty(audio, 'duration', { configurable: true, value: 2 })
    Object.defineProperty(audio, 'currentTime', { configurable: true, writable: true, value: 0 })
    fireEvent.loadedMetadata(audio)
    audio.currentTime = 1.9
    fireEvent.timeUpdate(audio)
    expect(screen.getByRole('button', { name: 'Seek voice-note.webm' })).toHaveAttribute('aria-valuenow', '95')

    fireEvent.ended(audio)

    const waveform = screen.getByTestId('chat-audio-waveform-preview')
    expect(screen.getByRole('button', { name: 'Seek voice-note.webm' })).toHaveAttribute('aria-valuenow', '100')
    expect(waveform.querySelectorAll('.opacity-80')).toHaveLength(CHAT_PREVIEW_PROFILE_V1.waveformSamples)
    expect(waveform.querySelectorAll('.opacity-25')).toHaveLength(0)
  })
})
