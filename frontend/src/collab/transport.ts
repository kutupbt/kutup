// WebSocket client for the collab relay. Reconnect with backoff, queue while
// disconnected, replay-from-seq on reconnect.

export interface PeerInfo {
  deviceId: number
  userId: string
  username?: string
}

export interface HelloMsg {
  type: 'hello'
  fileId: string
  currentDocKeyId: number
  headSeq: number
  /** Highest sender_seq this device has already persisted for this file.
   * The client resumes its outbound counter from here + 1 so refresh /
   * remount doesn't replay sequence numbers. 0 means this device has no
   * prior frames for this file. */
  mySenderSeqHigh: number
  peers: PeerInfo[]
}

/** Server pushes this whenever a peer joins or leaves the file's room.
 *  The OnlyOffice bridge needs it to feed connectState into the editor —
 *  without it, OO rejects remote saveChanges from unknown peers. */
export interface PeersMsg {
  type: 'peers'
  list: PeerInfo[]
  ts: number
}

export interface CollabTransportOpts {
  url: string                                       // ws URL with ?token=...&deviceId=...
  wsFactory?: (url: string) => WebSocket            // overridable for tests
  onFrame: (bytes: Uint8Array) => void
  onHello: (h: HelloMsg) => void
  onError: (e: unknown) => void
  /** Optional — fires when the server pushes an updated peer-list. */
  onPeers?: (p: PeersMsg) => void
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
          else if (obj.type === 'peers') this.opts.onPeers?.(obj as PeersMsg)
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
