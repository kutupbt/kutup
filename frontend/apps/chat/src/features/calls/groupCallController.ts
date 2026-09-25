import {
  BaseKeyProvider,
  createKeyMaterialFromBuffer,
  Room,
  RoomEvent,
  Track,
  type Participant,
} from 'livekit-client'
import type { ChatService } from '@kutup/chat-core/service'
import type { ChatCallMedia, ChatGroupCall, LocalMlsConversationRecord } from '@kutup/chat-core/types'
import { canonicalAccountAddress } from '@kutup/chat-core/identity'

// Group calls through the SFU of the server that started them, end-to-end
// encrypted (docs/chat-calls.md):
//
// - Frames are encrypted in the browser (insertable streams) with a key
//   exported from the group's MLS epoch; each epoch's key sits at its own
//   key index, so a removal changes the key and frames from members a step
//   behind still decrypt.
// - The SFU knows participants only by tags: HMAC(call secret, address)
//   plus a random suffix per join. Members map tags back to people from the
//   roster; the SFU cannot.
// - "Started" and "ended" travel to the group over MLS.

/** Key indexes the E2EE keyring holds (livekit-client's default). */
const KEYRING_SIZE = 16
/** How often the group's epoch is checked for a new key. */
const KEY_CHECK_MS = 3_000
const ENDED_SCREEN_MS = 2_000

export interface GroupCallParticipant {
  /** The SFU identity (a tag). */
  identity: string
  /** Who it is, when the tag matches a member. */
  address: string | null
  local: boolean
  audio: MediaStreamTrack | null
  video: MediaStreamTrack | null
  muted: boolean
  speaking: boolean
}

export interface GroupCallState {
  groupId: string
  call: ChatGroupCall
  phase: 'connecting' | 'active' | 'ended'
  participants: GroupCallParticipant[]
  muted: boolean
  cameraOn: boolean
  failed?: boolean
}

class EpochKeyProvider extends BaseKeyProvider {
  constructor() {
    super({ sharedKey: true, ratchetWindowSize: 0, failureTolerance: -1, keyringSize: KEYRING_SIZE })
  }

  async setEpochKey(key: Uint8Array, epoch: number): Promise<void> {
    const material = await createKeyMaterialFromBuffer(toArrayBuffer(key))
    this.onSetEncryptionKey(material, undefined, epoch % KEYRING_SIZE)
  }
}

type Listener = () => void

export class GroupCallController {
  private state: GroupCallState | null = null
  private readonly listeners = new Set<Listener>()
  private room: Room | null = null
  private keys: EpochKeyProvider | null = null
  private keyEpoch = -1
  private keyTimer: ReturnType<typeof setInterval> | null = null
  private clearTimer: ReturnType<typeof setTimeout> | null = null
  private releaseInCall: (() => void) | null = null
  private tags = new Map<string, string>()

  constructor(
    private readonly service: ChatService,
    private readonly account: string,
    private readonly groups: () => LocalMlsConversationRecord[],
  ) {}

  get current(): GroupCallState | null {
    return this.state
  }

  subscribe(listener: Listener): () => void {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  private set(next: GroupCallState | null): void {
    this.state = next
    for (const listener of this.listeners) listener()
  }

  private patch(patch: Partial<GroupCallState>): void {
    if (this.state) this.set({ ...this.state, ...patch })
  }

  /** Start a call in `groupId` on this server's SFU and join it. */
  async start(groupId: string, media: ChatCallMedia, host: string): Promise<void> {
    const call: ChatGroupCall = {
      callId: crypto.randomUUID(),
      event: 'started',
      host,
      roomId: hex(crypto.getRandomValues(new Uint8Array(16))),
      media,
      secret: base64(crypto.getRandomValues(new Uint8Array(32))),
    }
    await this.service.sendGroupCall(groupId, call)
    await this.join(groupId, call, media === 'video')
  }

  async join(groupId: string, call: ChatGroupCall, withVideo: boolean): Promise<void> {
    if (this.state && this.state.phase !== 'ended') throw new Error('already in a call')
    if (await this.inCallElsewhere()) throw new Error('already in a call')
    this.reset()
    await this.holdInCall()
    this.set({ groupId, call, phase: 'connecting', participants: [], muted: false, cameraOn: withVideo })
    try {
      const tagKey = await hmacKey(call.secret)
      this.tags = await memberTags(tagKey, this.roster(groupId))
      const identity = (await tag(tagKey, this.account)) + hex(crypto.getRandomValues(new Uint8Array(4)))
      const { url, token } = await this.service.groupCallToken(call.host, call.roomId, identity)
      const keys = new EpochKeyProvider()
      this.keys = keys
      await this.refreshKey()
      const room = new Room({
        adaptiveStream: true,
        dynacast: true,
        e2ee: {
          keyProvider: keys,
          worker: new Worker(new URL('livekit-client/e2ee-worker', import.meta.url), { type: 'module' }),
        },
      })
      this.room = room
      for (const event of [
        RoomEvent.ParticipantConnected,
        RoomEvent.ParticipantDisconnected,
        RoomEvent.TrackSubscribed,
        RoomEvent.TrackUnsubscribed,
        RoomEvent.TrackMuted,
        RoomEvent.TrackUnmuted,
        RoomEvent.LocalTrackPublished,
        RoomEvent.LocalTrackUnpublished,
        RoomEvent.ActiveSpeakersChanged,
      ]) {
        room.on(event, () => this.refreshParticipants())
      }
      room.on(RoomEvent.Disconnected, () => void this.ended(false))
      room.on(RoomEvent.EncryptionError, (error) => {
        console.warn('chat: group call frame decryption failed', error)
        // A member a key ahead: our epoch may be behind.
        void this.refreshKey()
      })
      await room.setE2EEEnabled(true)
      await room.connect(url, token)
      await room.localParticipant.setMicrophoneEnabled(true)
      if (withVideo) await room.localParticipant.setCameraEnabled(true)
      this.keyTimer = setInterval(() => void this.refreshKey(), KEY_CHECK_MS)
      this.patch({ phase: 'active' })
      this.refreshParticipants()
    } catch (error) {
      console.warn('chat: could not join the group call', error)
      this.patch({ failed: true })
      await this.ended(false)
      throw error
    }
  }

  /** Leave; the last one out tells the group the call ended. */
  async leave(): Promise<void> {
    if (!this.state || this.state.phase === 'ended') return
    const alone = (this.room?.remoteParticipants.size ?? 0) === 0
    await this.ended(alone)
  }

  toggleMute(): void {
    const room = this.room
    const state = this.state
    if (!room || !state) return
    const muted = !state.muted
    void room.localParticipant.setMicrophoneEnabled(!muted)
    this.patch({ muted })
  }

  async toggleCamera(): Promise<void> {
    const room = this.room
    const state = this.state
    if (!room || !state) return
    await room.localParticipant.setCameraEnabled(!state.cameraOn)
    this.patch({ cameraOn: !state.cameraOn })
    this.refreshParticipants()
  }

  dispose(): void {
    if (this.state && this.state.phase !== 'ended') void this.leave()
  }

  // --- Internals -------------------------------------------------------------

  private roster(groupId: string): string[] {
    const group = this.groups().find((record) => record.request.genesis.conversationId === groupId)
    return group?.currentRoster.map((member) => canonicalAccountAddress(member.address)) ?? []
  }

  /** Take the key of the group's current epoch, when it changed. */
  private async refreshKey(): Promise<void> {
    const state = this.state
    const keys = this.keys
    if (!state || !keys) return
    const { epoch, key } = await this.service.groupCallKey(state.groupId, state.call.callId)
    if (epoch === this.keyEpoch) return
    this.keyEpoch = epoch
    await keys.setEpochKey(key, epoch)
    // New members since the call began can be named too.
    if (state.phase === 'active') {
      this.tags = await memberTags(await hmacKey(state.call.secret), this.roster(state.groupId))
      this.refreshParticipants()
    }
  }

  private refreshParticipants(): void {
    const room = this.room
    if (!room || !this.state) return
    const speaking = new Set(room.activeSpeakers.map((participant) => participant.identity))
    const describe = (participant: Participant, local: boolean): GroupCallParticipant => {
      const audio = participant.getTrackPublication(Track.Source.Microphone)
      const video = participant.getTrackPublication(Track.Source.Camera)
      return {
        identity: participant.identity,
        address: local ? this.account : (this.tags.get(participant.identity.slice(0, 24)) ?? null),
        local,
        audio: local ? null : (audio?.track?.mediaStreamTrack ?? null),
        video: video && !video.isMuted ? (video.track?.mediaStreamTrack ?? null) : null,
        muted: !audio || audio.isMuted,
        speaking: speaking.has(participant.identity),
      }
    }
    this.patch({
      participants: [
        describe(room.localParticipant, true),
        ...[...room.remoteParticipants.values()].map((participant) => describe(participant, false)),
      ],
    })
  }

  private async ended(announce: boolean): Promise<void> {
    const state = this.state
    if (!state || state.phase === 'ended') return
    this.patch({ phase: 'ended' })
    if (this.keyTimer) clearInterval(this.keyTimer)
    this.keyTimer = null
    const room = this.room
    this.room = null
    await room?.disconnect().catch(() => undefined)
    this.releaseInCall?.()
    this.releaseInCall = null
    if (announce) {
      await this.service
        .sendGroupCall(state.groupId, { ...state.call, event: 'ended' })
        .catch((error: unknown) => console.warn('chat: could not announce the call ended', error))
    }
    this.clearTimer = setTimeout(() => {
      if (this.state?.call.callId === state.call.callId && this.state.phase === 'ended') this.set(null)
    }, ENDED_SCREEN_MS)
  }

  private reset(): void {
    if (this.clearTimer) clearTimeout(this.clearTimer)
    if (this.keyTimer) clearInterval(this.keyTimer)
    this.clearTimer = null
    this.keyTimer = null
    this.keys = null
    this.keyEpoch = -1
    this.tags = new Map()
    this.state = null
  }

  private async holdInCall(): Promise<void> {
    if (this.releaseInCall || !navigator.locks) return
    await new Promise<void>((granted) => {
      const held = new Promise<void>((resolve) => {
        this.releaseInCall = resolve
      })
      void navigator.locks
        .request(`kutup-chat-in-call:${this.account}`, { ifAvailable: true }, (lock) => {
          granted()
          return lock ? held : undefined
        })
        .catch(() => granted())
    })
  }

  private async inCallElsewhere(): Promise<boolean> {
    const snapshot = await navigator.locks?.query()
    return snapshot?.held?.some((lock) => lock.name === `kutup-chat-in-call:${this.account}`) ?? false
  }
}

/** The group call in progress in `history` for a group, if any: the latest start without its end. */
export function activeGroupCall(
  starts: ReadonlyArray<{ call: ChatGroupCall; atMs: number }>,
  nowMs: number,
): ChatGroupCall | null {
  const ended = new Set(starts.filter((item) => item.call.event === 'ended').map((item) => item.call.callId))
  const open = starts
    .filter((item) => item.call.event === 'started' && !ended.has(item.call.callId))
    // A call nobody ended (a crash) stops showing after half a day.
    .filter((item) => nowMs - item.atMs < 12 * 60 * 60 * 1000)
    .sort((a, b) => b.atMs - a.atMs)
  return open[0]?.call ?? null
}

async function hmacKey(secret: string): Promise<CryptoKey> {
  const bytes = Uint8Array.from(atob(secret), (char) => char.charCodeAt(0))
  return crypto.subtle.importKey('raw', bytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
}

/** The first 24 hex characters of HMAC(secret, address). */
async function tag(key: CryptoKey, address: string): Promise<string> {
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(address))
  return hex(new Uint8Array(mac)).slice(0, 24)
}

async function memberTags(key: CryptoKey, roster: string[]): Promise<Map<string, string>> {
  const entries = await Promise.all(roster.map(async (address) => [await tag(key, address), address] as const))
  return new Map(entries)
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

function base64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new ArrayBuffer(bytes.byteLength)
  new Uint8Array(copy).set(bytes)
  return copy
}
