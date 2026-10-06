// WebSocket client for the collab relay. Reconnect with backoff, queue while
// disconnected, replay-from-seq on reconnect.

import { reportCollabSocket, trackCollabTransport } from './connectivity'

export interface PeerInfo {
  deviceId: number
  userId: string
  username?: string
  /** Per-user presence color (hex '#rrggbb'). Drives the foreign-selection
   *  rectangle fill in office docs and the awareness cursor color in notes. */
  color?: string
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

/**
 * An office editing session's base (docs/onlyoffice.md, "Collaboration
 * sessions"): the version every tab in the room started from (null: the
 * original upload) and its log position. `yours`: the claim matched (or set)
 * it; `reset`: a restore replaced it, so this tab must reopen.
 */
export interface BaseMsg {
  type: 'base'
  versionId: string | null
  seq: number
  yours: boolean
  reset: boolean
}

export interface CollabTransportOpts {
  /**
   * The ws URL (with ?token=…&deviceId=…), or a function producing a current
   * one. Reconnects can come long after a 15-minute access token expired, so
   * apps pass `collabSocketUrl`, which is asked again on every connect.
   */
  url: string | (() => Promise<string>)
  wsFactory?: (url: string) => WebSocket            // overridable for tests
  /** May be async (frames are decrypted); a rejection is reported to onError. */
  onFrame: (bytes: Uint8Array) => void | Promise<void>
  onHello: (h: HelloMsg) => void
  onError: (e: unknown) => void
  /** Optional — fires when the server pushes an updated peer-list. */
  onPeers?: (p: PeersMsg) => void
  lastSeenSeq?: () => number                        // for resume on reconnect
  /** Control messages sent on every connect, before `resume` (an office
   *  editor's session-base claim). */
  openMessages?: () => object[]
  /** The room's session base, in answer to a claim or after a restore. */
  onBase?: (message: BaseMsg) => void
  /**
   * Log positions: `stored` after each kept frame (to everyone in the room,
   * the sender too) and `replayed` after the replay on connect. Messages are
   * handled strictly in order, so every frame before a position is applied.
   */
  onPosition?: (message: PositionMsg) => void | Promise<void>
}

export type PositionMsg =
  | { type: 'stored'; seq: number }
  | { type: 'replayed'; throughSeq: number; floor: number; since: number }

export class CollabTransport {
  private ws: WebSocket | null = null
  private pending: { bytes: Uint8Array; edit: boolean }[] = []
  private reconnectTimer: number | null = null
  private closed = false
  /** Messages are handled one after another, in arrival order. */
  private inbox: Promise<void> = Promise.resolve()
  /** The position this connection resumed from. */
  private resumedFrom = 0

  private readonly untrack: () => void

  constructor(private readonly opts: CollabTransportOpts) {
    this.untrack = trackCollabTransport(this)
    this.connect()
  }

  /** Number of frames queued while disconnected. Test helper. */
  pendingCount(): number { return this.pending.length }

  /** Queued frames that change the document (not presence or cursors). */
  pendingEditCount(): number { return this.pending.filter((frame) => frame.edit).length }

  /**
   * Send a binary frame. If disconnected, queues until next connect.
   * `edit`: the frame changes the document (a cursor or presence update
   * does not), so losing it would lose work.
   */
  send(b: Uint8Array, { edit = true }: { edit?: boolean } = {}): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(b)
    } else {
      this.pending.push({ bytes: b, edit })
    }
  }

  /** Permanently close the transport. No further connects. */
  close(): void {
    this.closed = true
    this.untrack()
    if (this.reconnectTimer != null) {
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
    this.ws?.close()
  }

  private connect(): void {
    if (this.closed) return
    if (typeof this.opts.url === 'string') {
      this.open(this.opts.url)
      return
    }
    this.opts.url().then(
      (url) => this.open(url),
      (e: unknown) => {
        this.opts.onError(e)
        this.scheduleReconnect()
      },
    )
  }

  private open(url: string): void {
    if (this.closed) return
    const factory = this.opts.wsFactory ?? ((u: string) => new WebSocket(u))
    let ws: WebSocket
    try {
      ws = factory(url)
    } catch (e) {
      this.opts.onError(e)
      this.scheduleReconnect()
      return
    }
    this.ws = ws
    ws.binaryType = 'arraybuffer'
    let opened = false

    ws.addEventListener('open', () => {
      opened = true
      reportCollabSocket(true)
      // Resume from last-seen seq on the server.
      const last = this.opts.lastSeenSeq?.() ?? 0
      this.resumedFrom = last
      for (const m of this.opts.openMessages?.() ?? []) ws.send(JSON.stringify(m))
      ws.send(JSON.stringify({ type: 'resume', lastSeenSeq: last }))
      // Drain queued outbound.
      for (const p of this.pending) ws.send(p.bytes)
      this.pending = []
    })

    ws.addEventListener('message', (ev) => {
      const resumedFrom = this.resumedFrom
      this.inbox = this.inbox
        .then(async () => {
          if (typeof ev.data === 'string') {
            let obj: { type?: string; seq?: number; throughSeq?: number; floor?: number }
            try {
              obj = JSON.parse(ev.data)
            } catch {
              return // ignore non-JSON text
            }
            if (obj.type === 'hello') this.opts.onHello(obj as HelloMsg)
            else if (obj.type === 'peers') this.opts.onPeers?.(obj as PeersMsg)
            else if (obj.type === 'base') this.opts.onBase?.(obj as BaseMsg)
            else if (obj.type === 'stored' && typeof obj.seq === 'number') {
              await this.opts.onPosition?.({ type: 'stored', seq: obj.seq })
            } else if (obj.type === 'replayed' && typeof obj.throughSeq === 'number') {
              await this.opts.onPosition?.({
                type: 'replayed',
                throughSeq: obj.throughSeq,
                floor: typeof obj.floor === 'number' ? obj.floor : 0,
                since: resumedFrom,
              })
            }
          } else {
            const arr = ev.data instanceof ArrayBuffer
              ? new Uint8Array(ev.data)
              : new Uint8Array(ev.data as ArrayBufferLike)
            await this.opts.onFrame(arr)
          }
        })
        .catch((e: unknown) => this.opts.onError(e))
    })

    ws.addEventListener('close', () => {
      // Closed before it ever opened: the network (or the server) refused it.
      if (!opened && !this.closed) reportCollabSocket(false)
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
