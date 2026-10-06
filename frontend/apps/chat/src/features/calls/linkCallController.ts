import { loadChatWasm } from '@kutup/chat-core/wasm'
import {
  callLinkToken,
  CallLinkRefused,
  decideKnock,
  knockMeeting,
  knockStatus,
  NoWaitingRoom,
  waitingPeople,
  WaitingRoomRequired,
  type CallLinkRefusal,
  type Knock,
  type OpenCallLink,
  type SfuAccess,
  type WaitingPerson,
} from '../callLinks/callLinks'
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

/** How often someone waiting asks whether they were let in. */
const KNOCK_POLL_MS = 2_500
/** How often the host looks at who is waiting. */
const WAITING_POLL_MS = 3_000

export interface LinkCallState {
  /** `waiting`: knocked, and waiting for the host to let this browser in. */
  phase: 'waiting' | 'connecting' | 'active' | 'ended'
  participants: LinkCallParticipant[]
  /** For the host: who is waiting to be let in, oldest first. */
  waiting: WaitingPerson[]
  /** This browser got into the meeting (as opposed to giving up at the door). */
  wasIn: boolean
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
  /** Each join attempt's number: a later one supersedes what an earlier one awaits. */
  private attempt = 0
  private waitingTimer: ReturnType<typeof setInterval> | null = null

  /**
   * `hostToken` is the owner's proof of being the host, when this browser
   * has it: it skips the waiting room and decides who is let in.
   */
  constructor(
    private readonly link: OpenCallLink,
    private readonly hostToken: string | null = null,
  ) {}

  /** Whether this browser is the meeting's host. */
  get isHost(): boolean {
    return this.hostToken !== null
  }

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

  /**
   * Join as `name`. With a waiting room (and no host token) this knocks and
   * waits to be let in first. Throws what stopped it; the state says why too.
   */
  async join(name: string, withVideo: boolean, waitingRoom: boolean): Promise<void> {
    if (this.state && this.state.phase !== 'ended') return
    const attempt = ++this.attempt
    const current = () => this.attempt === attempt && this.state !== null && this.state.phase !== 'ended'
    this.ownName = name.trim()
    const knocking = waitingRoom && !this.hostToken
    this.set({
      phase: knocking ? 'waiting' : 'connecting',
      participants: [],
      waiting: [],
      wasIn: false,
      messages: [],
      muted: false,
      cameraOn: withVideo,
      screenOn: false,
    })
    try {
      const wasm = await loadChatWasm()
      const label = wasm.callLinkSealName(this.link.secret, this.ownName)
      const participantId = hex(crypto.getRandomValues(new Uint8Array(16)))
      const access = await this.access(participantId, label, knocking, current)
      if (!access || !current()) return
      this.patch({ phase: 'connecting' })
      this.joinedAtMs = Date.now()
      this.leftAtMs = null
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
      await room.connect(access.url, access.token, withVideo)
      if (!current()) {
        await room.disconnect()
        return
      }
      this.patch({ phase: 'active', wasIn: true })
      await this.refresh()
      this.watchWaiting()
    } catch (error) {
      if (!current()) return
      console.warn('chat: could not join the call', error)
      const failure = error instanceof CallLinkRefused ? error.reason : mediaDenied(error) ? 'media' : 'unavailable'
      this.patch({ failure })
      await this.ended()
      throw error
    }
  }

  /**
   * The SFU token: asked for directly, or waited for at the door. Either
   * way may find the meeting's setting changed meanwhile and take the other.
   * Null when the attempt was given up while waiting.
   */
  private async access(participantId: string, label: string, knocking: boolean, current: () => boolean): Promise<SfuAccess | null> {
    if (!knocking) {
      try {
        return await callLinkToken(this.link, participantId, label, this.hostToken)
      } catch (error) {
        // A waiting room was turned on since the page looked.
        if (!(error instanceof WaitingRoomRequired)) throw error
        this.patch({ phase: 'waiting' })
      }
    }
    let knock: Knock
    try {
      knock = await knockMeeting(this.link, participantId, label)
    } catch (error) {
      // It was turned off since: the link alone lets this browser in.
      if (error instanceof NoWaitingRoom) return callLinkToken(this.link, participantId, label, this.hostToken)
      throw error
    }
    while (current()) {
      const answer = await knockStatus(this.link, knock)
      if (answer.status === 'admitted') return { url: answer.url, token: answer.token }
      if (answer.status === 'turnedAway') throw new CallLinkRefused('turnedAway')
      await new Promise((resolve) => setTimeout(resolve, KNOCK_POLL_MS))
    }
    return null
  }

  /** As the host: let in someone who is waiting. */
  async admit(knockId: string): Promise<void> {
    await this.decide(knockId, true)
  }

  /** As the host: turn away someone who is waiting. */
  async turnAway(knockId: string): Promise<void> {
    await this.decide(knockId, false)
  }

  private async decide(knockId: string, admit: boolean): Promise<void> {
    if (!this.hostToken || !this.state) return
    await decideKnock(this.link, this.hostToken, knockId, admit)
    this.patch({ waiting: this.state.waiting.filter((person) => person.knockId !== knockId) })
  }

  /** As the host, while in the meeting: keep looking at who is waiting. */
  private watchWaiting(): void {
    const hostToken = this.hostToken
    if (!hostToken || this.waitingTimer) return
    const look = async () => {
      if (this.state?.phase !== 'active') return
      try {
        const waiting = await waitingPeople(this.link, hostToken)
        if (this.state?.phase === 'active') this.patch({ waiting })
      } catch (error) {
        console.warn('chat: could not see who is waiting', error)
      }
    }
    void look()
    this.waitingTimer = setInterval(() => void look(), WAITING_POLL_MS)
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
    if (this.waitingTimer) clearInterval(this.waitingTimer)
    this.waitingTimer = null
    this.patch({ phase: 'ended', participants: [], waiting: [] })
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
