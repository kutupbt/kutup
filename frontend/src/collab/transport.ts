// WebSocket client for the collab relay. Reconnect with backoff, queue while
// disconnected, replay-from-seq on reconnect.

export interface HelloMsg {
  type: 'hello'
  fileId: string
  currentDocKeyId: number
  headSeq: number
  peers: { deviceId: number; userId: string }[]
}

export interface CollabTransportOpts {
  url: string                                       // ws URL with ?token=...&deviceId=...
  wsFactory?: (url: string) => WebSocket            // overridable for tests
  onFrame: (bytes: Uint8Array) => void
  onHello: (h: HelloMsg) => void
  onError: (e: unknown) => void
  lastSeenSeq?: () => number                        // for resume on reconnect
}

export class CollabTransport {
  private ws: WebSocket | null = null
  private pending: Uint8Array[] = []
  private reconnectTimer: number | null = null
  private closed = false

  constructor(private readonly opts: CollabTransportOpts) {
    this.connect()
  }

  /** Number of frames queued while disconnected. Test helper. */
  pendingCount(): number { return this.pending.length }

  /** Send a binary frame. If disconnected, queues until next connect. */
  send(b: Uint8Array): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(b)
    } else {
      this.pending.push(b)
    }
  }

  /** Permanently close the transport. No further connects. */
  close(): void {
    this.closed = true
    if (this.reconnectTimer != null) {
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
    this.ws?.close()
  }

  private connect(): void {
    if (this.closed) return
    const factory = this.opts.wsFactory ?? ((u: string) => new WebSocket(u))
    let ws: WebSocket
    try {
      ws = factory(this.opts.url)
    } catch (e) {
      this.opts.onError(e)
      this.scheduleReconnect()
      return
    }
    this.ws = ws
    ws.binaryType = 'arraybuffer'

    ws.addEventListener('open', () => {
      // Resume from last-seen seq on the server.
      const last = this.opts.lastSeenSeq?.() ?? 0
      ws.send(JSON.stringify({ type: 'resume', lastSeenSeq: last }))
      // Drain queued outbound.
      for (const p of this.pending) ws.send(p)
      this.pending = []
    })

    ws.addEventListener('message', (ev) => {
      if (typeof ev.data === 'string') {
        try {
          const obj = JSON.parse(ev.data)
          if (obj.type === 'hello') this.opts.onHello(obj as HelloMsg)
        } catch {
          // ignore non-JSON text
        }
      } else {
        const arr = ev.data instanceof ArrayBuffer
          ? new Uint8Array(ev.data)
          : new Uint8Array(ev.data as ArrayBufferLike)
        this.opts.onFrame(arr)
      }
    })

    ws.addEventListener('close', () => {
      if (!this.closed) this.scheduleReconnect()
    })
    ws.addEventListener('error', (e) => this.opts.onError(e))
  }

  private scheduleReconnect(): void {
    if (this.closed) return
    if (this.reconnectTimer != null) return
    this.reconnectTimer = window.setTimeout(() => {
      this.reconnectTimer = null
      this.connect()
    }, 1500)
  }
}
