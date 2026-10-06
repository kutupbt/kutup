import { loadChatWasm } from '@kutup/chat-core/wasm'
import {
  callLinkToken,
  CallLinkRefused,
  decideKnock,
  endMeeting,
  forgetMeetingSeat,
  knockMeeting,
  knockStatus,
  leaveKnock,
  lockMeeting,
  meetingRoles,
  meetingSeat,
  muteParticipant,
  NoWaitingRoom,
  removeParticipant,
  SeatGone,
  setCoHost,
  setScreenShare,
  waitingPeople,
  WaitingRoomRequired,
  type CallLinkRefusal,
  type HostProof,
  type Knock,
  type MeetingRole,
  type MeetingSeat,
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
// - A participant is a random identity to the SFU, bound to this browser by
//   its seat. The name each one chose travels sealed under another key from
//   the link; the others open it. Names are what people typed: nothing
//   verifies them. A participant who is signed in can also show their
//   account, which the server vouches for.
// - The meeting's hosts (its owner, and co-hosts) are what the server says
//   they are. A host removes and mutes people, stops a screen share and
//   locks the meeting; the owner ends it for everyone. All of these act at
//   the SFU, through the server.

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
/** Asking how a knock went may fail this long in a row (a dropped connection, a busy server) before the wait is given up. */
const KNOCK_GIVE_UP_MS = 90_000
/** How often a host looks at who is waiting. */
const WAITING_POLL_MS = 3_000
/**
 * How long after hearing the meeting has no host to ask again: by then the
 * server has made its longest-present participant a co-host.
 */
const NO_HOST_ASK_MS = 21_000

export interface LinkCallState {
  /** `waiting`: knocked, and waiting for a host to let this browser in. */
  phase: 'waiting' | 'connecting' | 'active' | 'ended'
  participants: LinkCallParticipant[]
  /** This browser's role in the meeting, once it is in. */
  role: MeetingRole | null
  /** A host locked the meeting: nobody new comes in. */
  locked: boolean
  /** For a host: who is waiting to be let in, oldest first. */
  waiting: WaitingPerson[]
  /** This browser got into the meeting (as opposed to giving up at the door). */
  wasIn: boolean
  /** What was written since this browser joined. Kept nowhere else. */
  messages: LinkCallMessage[]
  muted: boolean
  cameraOn: boolean
  screenOn: boolean
  /** Whether this browser may share its screen (a host can stop it). */
  canShare: boolean
  /** Counts the times a host muted this browser, so the page can say so. */
  mutedByHost: number
  /** Why joining failed, or why the stay ended, when it was not by leaving. */
  failure?: CallLinkRefusal | 'media'
}

export interface JoinOptions {
  withVideo: boolean
  /** What the page last heard: the meeting has a waiting room. */
  waitingRoom: boolean
  /**
   * The access token of the account signed in here, when the person chose
   * to show the others who they are; the server then vouches for it.
   */
  vouchFor?: () => Promise<string | null>
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
  private noHostTimer: ReturnType<typeof setTimeout> | null = null
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
  /** This browser is changing its own microphone: the change is not a host's. */
  private changingMicrophone = false

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
   * Join as `name`. With a waiting room (and neither the host token nor a
   * seat already let in) this knocks and waits to be let in first. Throws
   * what stopped it; the state says why too.
   */
  async join(name: string, { withVideo, waitingRoom, vouchFor }: JoinOptions): Promise<void> {
    if (this.state && this.state.phase !== 'ended') return
    const attempt = ++this.attempt
    const current = () => this.attempt === attempt && this.state !== null && this.state.phase !== 'ended'
    this.ownName = name.trim()
    this.set({
      phase: waitingRoom && !this.hostToken ? 'waiting' : 'connecting',
      participants: [],
      role: null,
      locked: false,
      waiting: [],
      wasIn: false,
      messages: [],
      muted: false,
      cameraOn: withVideo,
      screenOn: false,
      canShare: true,
      mutedByHost: 0,
    })
    try {
      const wasm = await loadChatWasm()
      const label = wasm.callLinkSealName(this.link.secret, this.ownName)
      // An account that cannot be vouched for now joins as a guest.
      const account = vouchFor ? await vouchFor().catch(() => null) : null
      const access = await this.access(label, account, current)
      if (!access || !current()) return
      this.patch({ phase: 'connecting' })
      this.joinedAtMs = Date.now()
      this.leftAtMs = null
      const room = new SfuRoom({
        changed: () => void this.refresh(),
        disconnected: (why) => {
          if (!this.ending && why !== 'other') this.patch({ failure: why === 'removed' ? 'removed' : 'endedByHost' })
          // Removed, or the meeting ended: this seat is no longer a way in.
          if (why !== 'other') forgetMeetingSeat(this.link.roomId)
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
   * The SFU token for this browser's seat. A seat that is gone (a host
   * removed it, or the meeting ended and started again) is replaced by a
   * new one, once: that one comes in like anyone new.
   */
  private async access(label: string, account: string | null, current: () => boolean): Promise<SfuAccess | null> {
    try {
      return await this.accessWith(meetingSeat(this.link.roomId), label, account, current)
    } catch (error) {
      if (!(error instanceof SeatGone)) throw error
      forgetMeetingSeat(this.link.roomId)
      try {
        return await this.accessWith(meetingSeat(this.link.roomId), label, account, current)
      } catch (again) {
        throw again instanceof SeatGone ? new CallLinkRefused('unavailable') : again
      }
    }
  }

  /**
   * Asked for directly, or waited for at the door: the server says which
   * (it lets the owner, and a seat already let in, straight through). Null
   * when the attempt was given up while waiting.
   */
  private async accessWith(seat: MeetingSeat, label: string, account: string | null, current: () => boolean): Promise<SfuAccess | null> {
    try {
      return await callLinkToken(this.link, seat, label, this.hostToken, account)
    } catch (error) {
      if (!(error instanceof WaitingRoomRequired)) throw error
      this.patch({ phase: 'waiting' })
    }
    let knock: Knock
    try {
      knock = await knockMeeting(this.link, seat, label, account)
    } catch (error) {
      // It was turned off since: the link alone lets this browser in.
      if (error instanceof NoWaitingRoom) return callLinkToken(this.link, seat, label, this.hostToken, account)
      throw error
    }
    // A knocker who closes the page stops waiting at once, not when the
    // host's list notices they stopped asking.
    const leave = () => leaveKnock(this.link, knock)
    window.addEventListener('pagehide', leave)
    try {
      let failingSince: number | null = null
      while (current()) {
        let answer: Awaited<ReturnType<typeof knockStatus>> | null = null
        try {
          answer = await knockStatus(this.link, knock)
          failingSince = null
        } catch (error) {
          // Unreachable or busy (a shared address over the rate limit) is
          // asked again; a knock that is gone (swept, the meeting deleted)
          // is final.
          if (error instanceof CallLinkRefused && error.reason !== 'unavailable' && error.reason !== 'busy') throw error
          failingSince ??= Date.now()
          if (Date.now() - failingSince > KNOCK_GIVE_UP_MS) throw error
        }
        if (answer?.status === 'admitted') return { url: answer.url, token: answer.token }
        if (answer?.status === 'turnedAway') throw new CallLinkRefused('turnedAway')
        await new Promise((resolve) => setTimeout(resolve, KNOCK_POLL_MS))
      }
      leave()
      return null
    } finally {
      window.removeEventListener('pagehide', leave)
    }
  }

  /** As a host: let in someone who is waiting. */
  async admit(knockId: string): Promise<void> {
    await this.decide(knockId, true)
  }

  /** As a host: turn away someone who is waiting. */
  async turnAway(knockId: string): Promise<void> {
    await this.decide(knockId, false)
  }

  /** As a host: let in everyone who is waiting. */
  async admitAll(): Promise<void> {
    for (const person of this.state?.waiting ?? []) {
      // One who stopped waiting meanwhile is not a reason to leave the rest out.
      await this.decide(person.knockId, true).catch(() => undefined)
    }
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
    if (proof) await removeParticipant(this.link, proof, identity)
  }

  /** As a host: mute someone's microphone. They can turn it back on. */
  async mute(identity: string): Promise<void> {
    const proof = this.hostProof()
    if (proof) await muteParticipant(this.link, proof, identity)
  }

  /** As a host: mute everyone who is not a host. */
  async muteAll(): Promise<void> {
    const proof = this.hostProof()
    if (proof) await muteParticipant(this.link, proof, null)
  }

  /** As a host: stop someone sharing their screen, or allow it again. */
  async setScreenShare(identity: string, allowed: boolean): Promise<void> {
    const proof = this.hostProof()
    if (proof) await setScreenShare(this.link, proof, identity, allowed)
  }

  /** As a host: lock the meeting (nobody new comes in) or unlock it. */
  async setLocked(locked: boolean): Promise<void> {
    const proof = this.hostProof()
    if (!proof) return
    await lockMeeting(this.link, proof, locked)
    this.patch({ locked })
    await this.hint()
  }

  /** As the owner: make a participant a co-host, or stop them being one. */
  async setCoHost(identity: string, enabled: boolean): Promise<void> {
    if (!this.hostToken) return
    await setCoHost(this.link, this.hostToken, identity, enabled)
    await this.hint()
    await this.askRoles()
  }

  /** Tell the others to ask the server how the meeting is set now. */
  private async hint(): Promise<void> {
    await this.room?.send(new Uint8Array(), ROLES_TOPIC).catch(() => undefined)
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
    forgetMeetingSeat(this.link.roomId)
    await this.ended()
  }

  /** What this browser shows the server to act as a host, if it is one. */
  private hostProof(): HostProof | null {
    if (this.hostToken) return { hostToken: this.hostToken }
    return this.state?.role === 'coHost' && this.sfuToken ? { sfuToken: this.sfuToken } : null
  }

  /**
   * Ask the server who the meeting's hosts are and how it is set. Asks made
   * while one is under way become a single further one.
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
          const { me, roles, locked, noHost } = await meetingRoles(this.link, proof)
          if (this.room !== room || !this.state) return
          this.roles = roles
          this.patch({
            role: me,
            locked,
            participants: this.state.participants.map((participant) => ({ ...participant, role: roles.get(participant.identity) ?? null })),
          })
          this.watchWaiting()
          if (this.noHostTimer) clearTimeout(this.noHostTimer)
          // Left without a host: the server names one shortly. Ask then.
          this.noHostTimer = noHost ? setTimeout(() => void this.askRoles(), NO_HOST_ASK_MS) : null
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

  async toggleMute(): Promise<void> {
    const room = this.room
    const state = this.state
    if (!room || !state) return
    const muted = !state.muted
    this.changingMicrophone = true
    this.patch({ muted })
    try {
      await room.setMicrophone(!muted)
    } finally {
      this.changingMicrophone = false
    }
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
    const state = this.state
    if (this.room !== room || !state) return
    const own = participants.find((participant) => participant.local)
    // The microphone went off without this browser turning it off: a host did.
    const mutedByHost = state.phase === 'active' && !this.changingMicrophone && !state.muted && own?.muted === true && room.microphonePublished
    this.patch({
      screenOn: room.screenOn,
      canShare: own?.canShare ?? true,
      ...(mutedByHost ? { muted: true, mutedByHost: state.mutedByHost + 1 } : {}),
      participants: participants.map(({ label, ...participant }) => ({
        ...participant,
        name: participant.local ? this.ownName : (this.names.get(label) ?? null),
        role: this.roles.get(participant.identity) ?? null,
      })),
    })
    // Someone came or went: the hosts may have with them (the owner joining
    // late, say). Asking is also what has the server look after the meeting:
    // remove again someone who was removed and is back with the SFU token
    // they still hold, and name a co-host when no host is left.
    const present = participants
      .map((participant) => participant.identity)
      .sort()
      .join(' ')
    if (present !== this.rolesFor && this.state?.phase === 'active') {
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
    if (this.noHostTimer) clearTimeout(this.noHostTimer)
    this.noHostTimer = null
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
