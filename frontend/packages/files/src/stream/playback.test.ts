import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { DEFAULT_STREAM_LIMITS, type StreamLimits } from './limits'
import { streamingAvailable, type PlayerStream } from './page'
import { openMediaPlayback, streamFallbackDecision, type MediaPlaybackSource, type PlaybackFallback } from './playback'

vi.mock('./page', async (original) => ({
  ...(await original<typeof import('./page')>()),
  streamingAvailable: vi.fn(() => Promise.resolve(true)),
}))

const SRC = '/sw/stream/AAAAAAAAAAAAAAAAAAAAAA'
const limits: StreamLimits = { ...DEFAULT_STREAM_LIMITS, blobFallbackMaxBytes: 100 }

/** A stream whose refusal the test sends, and a source that reads whole. */
function source(size = 10) {
  let refuse: (() => void) | null = null
  const stream: PlayerStream & { closed: boolean } = {
    src: SRC,
    size,
    closed: false,
    close: () => {
      stream.closed = true
    },
    onRefused: (listener) => {
      refuse = listener
      return () => {
        refuse = null
      }
    },
  }
  const readWhole = vi.fn<MediaPlaybackSource['readWhole']>(() => Promise.resolve(new Uint8Array(size)))
  const media: MediaPlaybackSource = {
    size,
    mimeType: 'video/mp4',
    limits: () => Promise.resolve(limits),
    stream: () => Promise.resolve(stream),
    readWhole,
  }
  return { media, stream, readWhole, refuse: () => refuse?.() }
}

describe('a stream’s fallback to a whole download', () => {
  it('falls back only before the first frame, once, within blob_fallback_max_bytes', () => {
    const fresh = { played: false, fellBack: false }
    expect(streamFallbackDecision(fresh, 'refused', 100, limits)).toBe('fallBack')
    expect(streamFallbackDecision(fresh, 'mediaError', 100, limits)).toBe('fallBack')
    expect(streamFallbackDecision(fresh, 'refused', 101, limits)).toBe('tooLarge')
    expect(streamFallbackDecision(fresh, 'firstFrame', 10, limits)).toBe('keep')
    // Once it has played, an error is the player's to show.
    expect(streamFallbackDecision({ played: true, fellBack: false }, 'mediaError', 10, limits)).toBe('keep')
    expect(streamFallbackDecision({ played: true, fellBack: false }, 'refused', 10, limits)).toBe('keep')
    expect(streamFallbackDecision({ played: false, fellBack: true }, 'refused', 10, limits)).toBe('keep')
  })

  describe('in a page', () => {
    let made = 0
    beforeEach(() => {
      made = 0
      URL.createObjectURL = vi.fn(() => `blob:test/${++made}`)
      URL.revokeObjectURL = vi.fn()
    })
    afterEach(() => {
      document.body.replaceChildren()
    })

    it('replaces a stream the worker refused with a Blob, and closes the stream', async () => {
      const { media, stream, readWhole, refuse } = source()
      const fallback = vi.fn<(next: PlaybackFallback) => void>()
      const playback = await openMediaPlayback(media, undefined, undefined, fallback)
      expect(playback).toMatchObject({ kind: 'ready', src: SRC, streamed: true })
      refuse()
      await vi.waitFor(() => expect(fallback).toHaveBeenCalledTimes(1))
      expect(fallback.mock.calls[0][0]).toMatchObject({ kind: 'ready', src: 'blob:test/1', streamed: false })
      expect(stream.closed).toBe(true)
      expect(readWhole).toHaveBeenCalledTimes(1)
      // A second refusal changes nothing; closing the first closes what replaced it.
      refuse()
      if (playback.kind === 'ready') playback.close()
      expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:test/1')
      expect(fallback).toHaveBeenCalledTimes(1)
    })

    it('falls back when the player fails before its first frame, not after', async () => {
      const failing = source()
      const fallback = vi.fn<(next: PlaybackFallback) => void>()
      await openMediaPlayback(failing.media, undefined, undefined, fallback)
      const video = document.createElement('video')
      video.setAttribute('src', SRC)
      document.body.append(video)
      video.dispatchEvent(new Event('error'))
      await vi.waitFor(() => expect(fallback).toHaveBeenCalledWith(expect.objectContaining({ kind: 'ready', streamed: false })))

      const playing = source()
      const later = vi.fn<(next: PlaybackFallback) => void>()
      const playback = await openMediaPlayback(playing.media, undefined, undefined, later)
      video.dispatchEvent(new Event('loadeddata'))
      video.dispatchEvent(new Event('error'))
      playing.refuse()
      await Promise.resolve()
      expect(later).not.toHaveBeenCalled()
      expect(playing.stream.closed).toBe(false)
      if (playback.kind === 'ready') playback.close()
      expect(playing.stream.closed).toBe(true)
    })

    it('ignores other elements’ errors', async () => {
      const { media } = source()
      const fallback = vi.fn<(next: PlaybackFallback) => void>()
      await openMediaPlayback(media, undefined, undefined, fallback)
      const other = document.createElement('video')
      other.setAttribute('src', '/sw/stream/BBBBBBBBBBBBBBBBBBBBBB')
      document.body.append(other)
      other.dispatchEvent(new Event('error'))
      await Promise.resolve()
      expect(fallback).not.toHaveBeenCalled()
    })

    it('says too large past blob_fallback_max_bytes, without reading', async () => {
      const { media, readWhole, refuse } = source(101)
      const fallback = vi.fn<(next: PlaybackFallback) => void>()
      await openMediaPlayback(media, undefined, undefined, fallback)
      refuse()
      expect(fallback).toHaveBeenCalledWith({ kind: 'tooLarge' })
      expect(readWhole).not.toHaveBeenCalled()
    })

    it('gives the Blob a media type only from the allowlist, else bytes', async () => {
      const made: Blob[] = []
      URL.createObjectURL = vi.fn((blob: Blob) => {
        made.push(blob)
        return `blob:test/${made.length}`
      })
      vi.mocked(streamingAvailable).mockResolvedValue(false)
      try {
        for (const [mimeType, expected] of [
          ['video/mp4', 'video/mp4'],
          ['Audio/MPEG; codecs=mp3', 'audio/mpeg'],
          ['text/html', 'application/octet-stream'],
          ['image/svg+xml', 'application/octet-stream'],
          ['', 'application/octet-stream'],
        ]) {
          const { media, readWhole } = source()
          media.mimeType = mimeType
          // A Blob read with a type of its own is retyped as well.
          readWhole.mockResolvedValueOnce(new Blob(['<html>'], { type: 'text/html' }))
          const playback = await openMediaPlayback(media)
          expect(playback).toMatchObject({ kind: 'ready', streamed: false })
          expect(made.at(-1)?.type, mimeType).toBe(expected)
        }
      } finally {
        vi.mocked(streamingAvailable).mockResolvedValue(true)
      }
    })

    it('says failed when the whole download fails', async () => {
      const { media, readWhole, refuse } = source()
      readWhole.mockRejectedValueOnce(new Error('offline'))
      const fallback = vi.fn<(next: PlaybackFallback) => void>()
      await openMediaPlayback(media, undefined, undefined, fallback)
      refuse()
      await vi.waitFor(() => expect(fallback).toHaveBeenCalledWith({ kind: 'failed' }))
    })
  })
})
