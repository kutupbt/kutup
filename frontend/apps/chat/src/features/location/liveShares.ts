import { conversationKey } from '@kutup/chat-core/identity'
import type { ChatLiveLocationV1, ConversationId } from '@kutup/chat-core/types'
import type { LiveLocationPosition } from '@kutup/crypto/liveLocation'
import { createStream, deleteStream, writeStream, type StreamSecrets } from './liveStream'

/**
 * The live locations this browser tab is sharing (docs/plans/maps.md "Live
 * location"). For each share: one stream on this account's server, written
 * with each new position (about every 15–30 s while moving, every 3 minutes
 * while still); a new stream and key every hour and as soon as anyone leaves
 * the group, handed to the remaining members only; stopped at the end time
 * or by the sharer. Sharing needs this tab open: browsers do not give
 * pages the location in the background.
 */

const MIN_INTERVAL_MS = 15_000
const HEARTBEAT_MS = 180_000
const MOVED_METRES = 25
const REKEY_MS = 3_600_000
const TICK_MS = 5_000
/** After a failed key hand-off or write, wait this long before trying again. */
const RETRY_MS = 30_000
const STORAGE_KEY = 'kutup.chat.liveShares.v1'

export interface ShareSender {
  sendLiveLocation(conversation: ConversationId, share: ChatLiveLocationV1, expiresAfterSeconds?: number): Promise<unknown>
  stopLiveLocation(conversation: ConversationId, shareId: string): Promise<unknown>
}

export interface LiveShareDeps {
  sender: ShareSender
  /** This account's server name: streams live there. */
  server: string
  /** This account's canonical address. */
  self: string
  /** A group's member accounts now; null for a 1:1 chat. */
  rosterOf: (conversation: ConversationId) => string[] | null
}

interface ActiveShare {
  shareId: string
  conversation: ConversationId
  untilMs: number
  generation: number
  stream: StreamSecrets
  generationStartedMs: number
  counter: number
  lastSentMs: number
  lastSent: { lat: number; lon: number } | null
  roster: string[] | null
  /** Not before this (after a failure). */
  retryAtMs?: number
}

export class LiveShareError extends Error {
  constructor(readonly reason: 'denied' | 'unavailable') {
    super(`location ${reason}`)
  }
}

function metresBetween(a: { lat: number; lon: number }, b: { lat: number; lon: number }): number {
  const rad = Math.PI / 180
  const dLat = (b.lat - a.lat) * rad
  const dLon = (b.lon - a.lon) * rad
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(a.lat * rad) * Math.cos(b.lat * rad) * Math.sin(dLon / 2) ** 2
  return 2 * 6_371_000 * Math.asin(Math.sqrt(h))
}

function positionOf(position: GeolocationPosition): LiveLocationPosition {
  return {
    lat: position.coords.latitude,
    lon: position.coords.longitude,
    accuracyM: position.coords.accuracy,
    atMs: position.timestamp || Date.now(),
  }
}

function currentPosition(): Promise<LiveLocationPosition> {
  return new Promise((resolve, reject) => {
    if (!('geolocation' in navigator)) {
      reject(new LiveShareError('unavailable'))
      return
    }
    navigator.geolocation.getCurrentPosition(
      (position) => resolve(positionOf(position)),
      (error) => reject(new LiveShareError(error.code === error.PERMISSION_DENIED ? 'denied' : 'unavailable')),
      { enableHighAccuracy: true, timeout: 20_000, maximumAge: 30_000 },
    )
  })
}

function bodyOf(share: ActiveShare, server: string): ChatLiveLocationV1 {
  return {
    shareId: share.shareId,
    generation: share.generation,
    server,
    streamId: share.stream.streamId,
    key: share.stream.key,
    readCapability: share.stream.readCapability,
    untilMs: share.untilMs,
  }
}

class LiveShares {
  private shares = new Map<string, ActiveShare>()
  private busy = new Set<string>()
  private latest: LiveLocationPosition | null = null
  private watchId: number | null = null
  private timer: number | null = null
  private deps: LiveShareDeps | null = null
  private listeners = new Set<() => void>()
  private snapshot: readonly string[] = []

  /** Ids of the shares running here, for React. */
  getSnapshot = (): readonly string[] => this.snapshot

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  isSharing(shareId: string): boolean {
    return this.shares.has(shareId)
  }

  /** Whether this tab is sharing in a conversation. */
  sharingIn(conversation: ConversationId): boolean {
    const key = conversationKey(conversation)
    return [...this.shares.values()].some((share) => conversationKey(share.conversation) === key)
  }

  /** Connect to the open chat; resumes shares this tab had before a reload. */
  attach(deps: LiveShareDeps): void {
    this.deps = deps
    for (const share of this.restore()) this.shares.set(share.shareId, share)
    this.changed()
  }

  detach(): void {
    this.deps = null
    this.stopWatching()
  }

  /** Start sharing this device's location in a conversation for `durationMs`. */
  async start(conversation: ConversationId, durationMs: number, expiresAfterSeconds?: number): Promise<void> {
    const deps = this.requireDeps()
    this.latest = await currentPosition()
    const now = Date.now()
    const untilMs = now + durationMs
    const stream = await createStream(untilMs)
    const share: ActiveShare = {
      shareId: crypto.randomUUID(),
      conversation,
      untilMs,
      generation: 1,
      stream,
      generationStartedMs: now,
      counter: 0,
      lastSentMs: 0,
      lastSent: null,
      roster: deps.rosterOf(conversation),
    }
    // The first position is in the stream before anyone is told about it.
    await this.push(share, true)
    try {
      await deps.sender.sendLiveLocation(conversation, bodyOf(share, deps.server), expiresAfterSeconds)
    } catch (error) {
      await deleteStream(stream).catch(() => undefined)
      throw error
    }
    this.shares.set(share.shareId, share)
    this.changed()
  }

  /** The sharer stops: tell the conversation, then end the stream. */
  async stop(shareId: string): Promise<void> {
    const share = this.shares.get(shareId)
    if (!share) return
    await this.requireDeps().sender.stopLiveLocation(share.conversation, shareId)
    await this.finish(share)
  }

  /** Another of this account's devices stopped it: end the stream here too. */
  async ended(shareId: string): Promise<void> {
    const share = this.shares.get(shareId)
    if (share) await this.finish(share)
  }

  private requireDeps(): LiveShareDeps {
    if (!this.deps) throw new Error('chat is not open')
    return this.deps
  }

  private async finish(share: ActiveShare): Promise<void> {
    this.shares.delete(share.shareId)
    this.changed()
    await deleteStream(share.stream).catch(() => undefined)
  }

  private changed(): void {
    this.snapshot = [...this.shares.keys()]
    this.persist()
    if (this.shares.size > 0 && this.deps) this.startWatching()
    else this.stopWatching()
    for (const listener of this.listeners) listener()
  }

  private startWatching(): void {
    if (this.watchId === null && 'geolocation' in navigator) {
      this.watchId = navigator.geolocation.watchPosition(
        (position) => {
          this.latest = positionOf(position)
        },
        () => undefined,
        { enableHighAccuracy: true, maximumAge: 10_000 },
      )
    }
    if (this.timer === null) this.timer = window.setInterval(() => void this.tick(), TICK_MS)
  }

  private stopWatching(): void {
    if (this.watchId !== null) navigator.geolocation.clearWatch(this.watchId)
    if (this.timer !== null) window.clearInterval(this.timer)
    this.watchId = null
    this.timer = null
  }

  private async tick(): Promise<void> {
    const deps = this.deps
    if (!deps) return
    const now = Date.now()
    for (const share of [...this.shares.values()]) {
      if (this.busy.has(share.shareId) || (share.retryAtMs ?? 0) > now) continue
      this.busy.add(share.shareId)
      try {
        if (now >= share.untilMs) {
          await this.finish(share)
          continue
        }
        const roster = deps.rosterOf(share.conversation)
        if (roster && roster.every((account) => account === deps.self)) {
          // Nobody else is left to see it.
          await this.finish(share)
          continue
        }
        const someoneLeft = Boolean(share.roster && roster && share.roster.some((account) => !roster.includes(account)))
        if (someoneLeft || now - share.generationStartedMs >= REKEY_MS) {
          await this.rekey(share, roster)
        } else {
          await this.push(share, false)
        }
      } catch {
        // Offline, or the group is mid-change: try again a little later.
        share.retryAtMs = Date.now() + RETRY_MS
      } finally {
        this.busy.delete(share.shareId)
      }
    }
  }

  /** Write the latest position when it is due; a stream that is gone is replaced. */
  private async push(share: ActiveShare, force: boolean): Promise<void> {
    const position = this.latest
    if (!position) return
    const now = Date.now()
    const moved = !share.lastSent || metresBetween(share.lastSent, position) >= MOVED_METRES
    const due = force || now - share.lastSentMs >= HEARTBEAT_MS || (moved && now - share.lastSentMs >= MIN_INTERVAL_MS)
    if (!due) return
    share.counter += 1
    const result = await writeStream(share.stream, share.counter, position)
    if (result === 'written') {
      share.lastSentMs = now
      share.lastSent = { lat: position.lat, lon: position.lon }
      this.persist()
    } else if (result === 'gone' && this.shares.has(share.shareId)) {
      await this.rekey(share, this.requireDeps().rosterOf(share.conversation))
    }
  }

  /**
   * A new stream and key, handed to whoever is in the conversation now, then
   * the old stream deleted: someone who left keeps only a key to nothing.
   */
  private async rekey(share: ActiveShare, roster: string[] | null): Promise<void> {
    const deps = this.requireDeps()
    const old = share.stream
    const next: ActiveShare = {
      ...share,
      generation: share.generation + 1,
      stream: await createStream(share.untilMs),
      generationStartedMs: Date.now(),
      counter: 0,
      lastSentMs: 0,
      roster,
    }
    try {
      await this.push(next, true)
      await deps.sender.sendLiveLocation(share.conversation, bodyOf(next, deps.server))
    } catch (error) {
      // Nobody has this stream's key: remove it rather than leave it open.
      await deleteStream(next.stream).catch(() => undefined)
      throw error
    }
    Object.assign(share, next, { retryAtMs: undefined })
    this.persist()
    await deleteStream(old).catch(() => undefined)
  }

  // A reload keeps the shares (this tab only; secrets never leave it).
  private persist(): void {
    try {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify([...this.shares.values()]))
    } catch {
      // Storage unavailable: a reload ends the shares at their end time.
    }
  }

  private restore(): ActiveShare[] {
    try {
      const raw = sessionStorage.getItem(STORAGE_KEY)
      const shares = raw ? (JSON.parse(raw) as ActiveShare[]) : []
      return shares.filter((share) => share.untilMs > Date.now())
    } catch {
      return []
    }
  }
}

export const liveShares = new LiveShares()
