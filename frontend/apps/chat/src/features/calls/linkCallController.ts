import { loadChatWasm } from '@kutup/chat-core/wasm'
import {
  callLinkToken,
  CallLinkRefused,
  decideKnock,
  endMeeting,
  knockMeeting,
  knockStatus,
  meetingRoles,
  NoWaitingRoom,
  removeParticipant,
  setCoHost,
  waitingPeople,
  WaitingRoomRequired,
  type CallLinkRefusal,
  type HostProof,
  type Knock,
  type MeetingRole,
  type OpenCallLink,
  type SfuAccess,
  type WaitingPerson,
} from '../callLinks/callLinks'
import { CHAT_TOPIC, ROLES_TOPIC, SfuRoom, type SfuParticipant } from './sfuRoom'

// A call through a link (docs/chat-calls.md): anyone holding the link joins,
// with or without an account.
//
// - Media goes through the SFU of the link's server, its frames encrypted in
//   the browser under a key from the link, so the SFU forwards what it
//   cannot read.
// - A participant is a random identity to the SFU. The name each one chose
//   travels sealed under another key from the link; the others open it.
//   Names are what people typed: nothing verifies them.
// - The meeting's hosts (its owner, and the co-hosts the owner names) are
//   what the server says they are. A host removes people; the owner ends
//   the meeting for everyone. Both act at the SFU, through the server.

export interface LinkCallParticipant extends Omit<SfuParticipant, 'label'> {
  /** The name this participant chose; null when its label does not open. */
  name: string | null
  /** Whether this participant hosts the meeting. */
  role: MeetingRole | null
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
  /** This browser's role in the meeting, once it is in. */
  role: MeetingRole | null
  /** For a host: who is waiting to be let in, oldest first. */
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
  /** This browser's SFU token: how a co-host says who it is. */
  private sfuToken: string | null = null
  /** The meeting's hosts by SFU identity, as the server last said. */
  private roles = new Map<string, MeetingRole>()
  private rolesAsked: Promise<void> | null = null
  private rolesStale = false
  /** The identities in the room when the hosts were last asked for. */
  private rolesFor = ''
  /** This browser is ending the meeting: its own disconnection is no surprise. */
  private ending = false

  /**
   * `hostToken` is the owner's proof of being the host, when this browser
   * has it: it skips the waiting room and decides who is let in.
   */
  constructor(
    private readonly link: OpenCallLink,
    private readonly hostToken: string | null = null,
  ) {}

  /** Whether this browser is the meeting's owner. */
  get isOwner(): boolean {
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
      role: null,
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
        disconnected: (why) => {
          if (!this.ending && why !== 'other') this.patch({ failure: why === 'removed' ? 'removed' : 'endedByHost' })
          void this.ended()
        },
        // One key for the whole call: a frame that does not decrypt was not
        // encrypted by a holder of this link.
        decryptionFailed: () => undefined,
        data: (identity, payload, topic) => {
          if (topic === CHAT_TOPIC) void this.received(identity, payload)
          // The hint carries nothing and proves nothing: the server is asked.
          else if (topic === ROLES_TOPIC) void this.askRoles()
        },
      })
      this.room = room
      this.sfuToken = access.token
      this.ending = false
      await room.keys.set(Uint8Array.from(atob(this.link.frameKey), (char) => char.charCodeAt(0)), 0)
      await room.connect(access.url, access.token, withVideo)
      if (!current()) {
        await room.disconnect()
        return
      }
      this.patch({ phase: 'active', wasIn: true })
      // Finding who is in the room asks the server who its hosts are.
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

  /** As a host: let in someone who is waiting. */
  async admit(knockId: string): Promise<void> {
    await this.decide(knockId, true)
  }

  /** As a host: turn away someone who is waiting. */
  async turnAway(knockId: string): Promise<void> {
    await this.decide(knockId, false)
  }

  private async decide(knockId: string, admit: boolean): Promise<void> {
    const proof = this.hostProof()
    if (!proof || !this.state) return
    await decideKnock(this.link, proof, knockId, admit)
    this.patch({ waiting: this.state.waiting.filter((person) => person.knockId !== knockId) })
  }

  /**
   * As a host: remove someone from the meeting. The server turns the
   * waiting room on with it, since they still hold the link.
   */
  async remove(identity: string): Promise<void> {
    const proof = this.hostProof()
    if (!proof) return
    await removeParticipant(this.link, proof, identity)
  }

  /** As the owner: make a participant a co-host, or stop them being one. */
  async setCoHost(identity: string, enabled: boolean): Promise<void> {
    if (!this.hostToken) return
    await setCoHost(this.link, this.hostToken, identity, enabled)
    // Tell the others to ask the server who the hosts are now.
    await this.room?.send(new Uint8Array(), ROLES_TOPIC).catch(() => undefined)
    await this.askRoles()
  }

  /** As the owner: end the meeting for everyone in it. */
  async endForAll(): Promise<void> {
    if (!this.hostToken) return
    this.ending = true
    try {
      await endMeeting(this.link, this.hostToken)
    } catch (error) {
      this.ending = false
      throw error
    }
    await this.ended()
  }

  /** What this browser shows the server to act as a host, if it is one. */
  private hostProof(): HostProof | null {
    if (this.hostToken) return { hostToken: this.hostToken }
    return this.state?.role === 'coHost' && this.sfuToken ? { sfuToken: this.sfuToken } : null
  }

  /**
   * Ask the server who the meeting's hosts are. Asks made while one is
   * under way become a single further one.
   */
  private askRoles(): Promise<void> {
    if (this.rolesAsked) {
      this.rolesStale = true
      return this.rolesAsked
    }
    const room = this.room
    const ask = async () => {
      do {
        this.rolesStale = false
        if (!room || this.room !== room || this.state?.phase !== 'active') return
        try {
          const proof: HostProof | null = this.hostToken ? { hostToken: this.hostToken } : this.sfuToken ? { sfuToken: this.sfuToken } : null
          const { me, roles } = await meetingRoles(this.link, proof)
          if (this.room !== room || !this.state) return
          this.roles = roles
          this.patch({
            role: me,
            participants: this.state.participants.map((participant) => ({ ...participant, role: roles.get(participant.identity) ?? null })),
          })
          this.watchWaiting()
        } catch (error) {
          console.warn('chat: could not learn who hosts the meeting', error)
        }
      } while (this.rolesStale)
    }
    this.rolesAsked = ask().finally(() => {
      this.rolesAsked = null
    })
    return this.rolesAsked
  }

  /** While a host in the meeting: keep looking at who is waiting. */
  private watchWaiting(): void {
    if (!this.hostProof()) {
      if (this.waitingTimer) clearInterval(this.waitingTimer)
      this.waitingTimer = null
      if (this.state?.waiting.length) this.patch({ waiting: [] })
      return
    }
    if (this.waitingTimer) return
    const look = async () => {
      const proof = this.hostProof()
      if (!proof || this.state?.phase !== 'active') return
      try {
        const waiting = await waitingPeople(this.link, proof)
        if (this.state?.phase === 'active' && this.hostProof()) this.patch({ waiting })
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
        role: this.roles.get(participant.identity) ?? null,
      })),
    })
    // Someone came or went: the hosts may have with them (the owner joining
    // late, say). Asking is also what has the server remove again someone
    // who was removed and is back with the SFU token they still hold.
    const present = participants.map((participant) => participant.identity).sort().join(' ')
    if (present !== this.rolesFor && this.state.phase === 'active') {
      this.rolesFor = present
      void this.askRoles()
    }
  }

  private async ended(): Promise<void> {
    const state = this.state
    if (!state || state.phase === 'ended') return
    this.leftAtMs = Date.now()
    if (this.waitingTimer) clearInterval(this.waitingTimer)
    this.waitingTimer = null
    this.patch({ phase: 'ended', participants: [], waiting: [], role: null })
    const room = this.room
    this.room = null
    this.sfuToken = null
    this.roles = new Map()
    this.rolesFor = ''
    await room?.disconnect()
  }
}

function mediaDenied(error: unknown): boolean {
  return error instanceof DOMException && (error.name === 'NotAllowedError' || error.name === 'NotFoundError')
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}
