import { describe, expect, it, vi } from 'vitest'
import { isStreamChunkRequest, STREAM_PROTOCOL_VERSION, type StreamChunkAnswer } from '../blockReader/protocol'
import { DEFAULT_STREAM_LIMITS } from './limits'
import { onServiceWorkerMessage, openPlayerStream, RELOAD_NEEDED_EVENT, TooManyStreams } from './page'

/** A port whose answers the test reads. */
function port() {
  const sent: StreamChunkAnswer[] = []
  return { sent, port: { postMessage: (message: StreamChunkAnswer) => sent.push(message), close: vi.fn() } as unknown as MessagePort & { close: ReturnType<typeof vi.fn> } }
}

const request = (accepts: number[], streamId = 'AAAAAAAAAAAAAAAAAAAAAA') => ({
  type: 'get_stream_chunk',
  v: Math.max(...accepts),
  accepts,
  streamId,
  range: { start: 0, end: 1 },
})

describe('the page’s stream glue', () => {
  it('takes only well-formed stream requests', () => {
    expect(isStreamChunkRequest(request([1]))).toBe(true)
    expect(isStreamChunkRequest({ ...request([1]), range: { suffix: 10 } })).toBe(true)
    expect(isStreamChunkRequest({ ...request([1]), range: { start: -1, end: null } })).toBe(false)
    expect(isStreamChunkRequest({ ...request([1]), range: { suffix: 0 } })).toBe(false)
    expect(isStreamChunkRequest({ ...request([1]), type: 'other' })).toBe(false)
    expect(isStreamChunkRequest({ type: 'get_stream_chunk', streamId: 'x' })).toBe(false)
    expect(isStreamChunkRequest(null)).toBe(false)
  })

  it('answers a worker of another protocol version with "version" and asks for a reload, once', async () => {
    const reload = vi.fn()
    window.addEventListener(RELOAD_NEEDED_EVENT, reload)
    try {
      const first = port()
      onServiceWorkerMessage({ data: request([STREAM_PROTOCOL_VERSION + 1]), ports: [first.port] })
      expect(first.sent).toEqual([{ v: STREAM_PROTOCOL_VERSION, kind: 'version' }])
      expect(first.port.close).toHaveBeenCalled()
      const second = port()
      onServiceWorkerMessage({ data: request([STREAM_PROTOCOL_VERSION + 1]), ports: [second.port] })
      await vi.waitFor(() => expect(reload).toHaveBeenCalledTimes(1))
    } finally {
      window.removeEventListener(RELOAD_NEEDED_EVENT, reload)
    }
  })

  it('answers a request for a stream it doesn’t have with an error, at once', () => {
    const { sent, port: p } = port()
    onServiceWorkerMessage({ data: request([STREAM_PROTOCOL_VERSION]), ports: [p] })
    expect(sent).toEqual([{ v: STREAM_PROTOCOL_VERSION, kind: 'error', message: 'no such stream' }])
  })

  it('ignores messages that aren’t stream requests, or come without a port', () => {
    const { sent, port: p } = port()
    onServiceWorkerMessage({ data: { type: 'something' }, ports: [p] })
    onServiceWorkerMessage({ data: request([STREAM_PROTOCOL_VERSION]), ports: [] })
    expect(sent).toEqual([])
  })

  it('holds a tab to drive.stream.max_concurrent streams', async () => {
    await expect(
      openPlayerStream({
        url: '/api/files/x/download',
        fileKey: new Uint8Array(32),
        expected: { fileId: 'x', generation: 1, content: { revisionId: 'r', manifestSha256: 'm' }, size: 1 },
        accessToken: '',
        mimeType: 'video/mp4',
        limits: { ...DEFAULT_STREAM_LIMITS, maxConcurrent: 0 },
      }),
    ).rejects.toBeInstanceOf(TooManyStreams)
  })
})
