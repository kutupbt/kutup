import { loadChatWasm } from '@kutup/chat-core/wasm'
import { callLinkToken, CallLinkRefused, type CallLinkRefusal, type OpenCallLink } from '../callLinks/callLinks'
import { SfuRoom, type SfuParticipant } from './sfuRoom'

// A call through a link (docs/chat-calls.md): anyone holding the link joins,
// with or without an account.
//
// - Media goes through the SFU of the link's server, its frames encrypted in
//   the browser under a key from the link, so the SFU forwards what it
//   cannot read.
// - A participant is a random identity to the SFU. The name each one chose
//   travels sealed under another key from the link; the others open it.
//   Names are what people typed: nothing verifies them.

export interface LinkCallParticipant extends Omit<SfuParticipant, 'label'> {
  /** The name this participant chose; null when its label does not open. */
  name: string | null
}

/** A message written in the meeting, while this browser was in it. */
export interface LinkCallMessage {
  id: string
  /** The SFU identity it came from. */
  identity: string
  own: boolean
  /** The sender's chosen name when it was written; null when unknown. */
  name: string | null
  text: string
  sentAtMs: number
}

/** Messages kept while in the meeting; older ones drop off. */
const MAX_MESSAGES = 500

export interface LinkCallState {
  phase: 'connecting' | 'active' | 'ended'
  participants: LinkCallParticipant[]
  /** What was written since this browser joined. Kept nowhere else. */
  messages: LinkCallMessage[]
  muted: boolean
  cameraOn: boolean
  screenOn: boolean
  /** Why joining failed, when it did. */
  failure?: CallLinkRefusal | 'media'
}

type Listener = () => void

export class LinkCallController {
  private state: LinkCallState | null = null
  private readonly listeners = new Set<Listener>()
  private room: SfuRoom | null = null
  /** Sealed label → opened name (null: does not open), so each opens once. */
  private readonly names = new Map<string, string | null>()
  private ownName = ''
  private joinedAtMs = 0
  private leftAtMs: number | null = null

  constructor(private readonly link: OpenCallLink) {}

  /** A snapshot for useSyncExternalStore. */
  readonly current = (): LinkCallState | null => this.state

  readonly subscribe = (listener: Listener): (() => void) => {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  private set(next: LinkCallState | null): void {
    this.state = next
    for (const listener of this.listeners) listener()
  }

  private patch(patch: Partial<LinkCallState>): void {
    if (this.state) this.set({ ...this.state, ...patch })
  }

  /** Join as `name`. Throws what stopped it; the state says why too. */
  async join(name: string, withVideo: boolean): Promise<void> {
    if (this.state && this.state.phase !== 'ended') return
    this.ownName = name.trim()
    this.set({ phase: 'connecting', participants: [], messages: [], muted: false, cameraOn: withVideo, screenOn: false })
    this.joinedAtMs = Date.now()
    this.leftAtMs = null
    try {
      const wasm = await loadChatWasm()
      const label = wasm.callLinkSealName(this.link.secret, this.ownName)
      const participantId = hex(crypto.getRandomValues(new Uint8Array(16)))
      const { url, token } = await callLinkToken(this.link, participantId, label)
      const room = new SfuRoom({
        changed: () => void this.refresh(),
        disconnected: () => void this.ended(),
        // One key for the whole call: a frame that does not decrypt was not
        // encrypted by a holder of this link.
        decryptionFailed: () => undefined,
        data: (identity, payload) => void this.received(identity, payload),
      })
      this.room = room
      await room.keys.set(Uint8Array.from(atob(this.link.frameKey), (char) => char.charCodeAt(0)), 0)
      await room.connect(url, token, withVideo)
      this.patch({ phase: 'active' })
      await this.refresh()
    } catch (error) {
      console.warn('chat: could not join the call', error)
      const failure = error instanceof CallLinkRefused ? error.reason : mediaDenied(error) ? 'media' : 'unavailable'
      this.patch({ failure })
      await this.ended()
      throw error
    }
  }

  async leave(): Promise<void> {
    await this.ended()
  }

  toggleMute(): void {
    const room = this.room
    const state = this.state
    if (!room || !state) return
    const muted = !state.muted
    void room.setMicrophone(!muted)
    this.patch({ muted })
  }

  async toggleCamera(): Promise<void> {
    const room = this.room
    const state = this.state
    if (!room || !state) return
    await room.setCamera(!state.cameraOn)
    this.patch({ cameraOn: !state.cameraOn })
    await this.refresh()
  }

  async toggleScreen(): Promise<void> {
    const room = this.room
    const state = this.state
    if (!room || !state) return
    await room.setScreen(!state.screenOn)
    await this.refresh()
  }

  /**
   * Write a message to everyone in the meeting. It travels through the SFU
   * sealed under a key from the link and is stored nowhere: someone who
   * joins later does not see it.
   */
  async send(text: string): Promise<void> {
    const room = this.room
    const trimmed = text.trim()
    if (!room || !this.state || this.state.phase !== 'active' || !trimmed) return
    const wasm = await loadChatWasm()
    const message = { id: hex(crypto.getRandomValues(new Uint8Array(16))), text: trimmed, sentAtMs: Date.now() }
    const sealed = wasm.callLinkSealMessage(this.link.secret, message)
    await room.send(new TextEncoder().encode(sealed))
    this.append({ ...message, identity: room.localIdentity, own: true, name: this.ownName })
  }

  /** How long this browser has been (or was) in the meeting, and since when. */
  get joined(): { atMs: number; seconds: number } {
    const until = this.leftAtMs ?? Date.now()
    return { atMs: this.joinedAtMs, seconds: Math.max(0, Math.round((until - this.joinedAtMs) / 1000)) }
  }

  dispose(): void {
    void this.ended()
  }

  private async received(identity: string, payload: Uint8Array): Promise<void> {
    const wasm = await loadChatWasm()
    let message: { id: string; text: string; sentAtMs: number }
    try {
      message = wasm.callLinkOpenMessage(this.link.secret, new TextDecoder().decode(payload))
    } catch {
      // Not sealed by a holder of this link: not a message of this meeting.
      return
    }
    const label = this.room?.participants().find((participant) => participant.identity === identity)?.label
    this.append({ ...message, identity, own: false, name: label ? (this.names.get(label) ?? null) : null })
  }

  private append(message: LinkCallMessage): void {
    const state = this.state
    if (!state || state.messages.some((other) => other.id === message.id && other.identity === message.identity)) return
    this.patch({ messages: [...state.messages, message].slice(-MAX_MESSAGES) })
  }

  private async refresh(): Promise<void> {
    const room = this.room
    if (!room || !this.state) return
    const participants = room.participants()
    const wasm = await loadChatWasm()
    for (const { label, local } of participants) {
      if (local || !label || this.names.has(label)) continue
      try {
        this.names.set(label, wasm.callLinkOpenName(this.link.secret, label))
      } catch {
        this.names.set(label, null)
      }
    }
    if (this.room !== room || !this.state) return
    this.patch({
      screenOn: room.screenOn,
      participants: participants.map(({ label, ...participant }) => ({
        ...participant,
        name: participant.local ? this.ownName : (this.names.get(label) ?? null),
      })),
    })
  }

  private async ended(): Promise<void> {
    const state = this.state
    if (!state || state.phase === 'ended') return
    this.leftAtMs = Date.now()
    this.patch({ phase: 'ended', participants: [] })
    const room = this.room
    this.room = null
    await room?.disconnect()
  }
}

function mediaDenied(error: unknown): boolean {
  return error instanceof DOMException && (error.name === 'NotAllowedError' || error.name === 'NotFoundError')
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}
