import {
  BaseKeyProvider,
  createKeyMaterialFromBuffer,
  DisconnectReason,
  Room,
  RoomEvent,
  Track,
  type Participant,
} from 'livekit-client'

// A call's room on an SFU, as group calls and call links both use it
// (docs/chat-calls.md): media frames are encrypted in the browser
// (insertable streams) under keys the caller supplies, so the SFU forwards
// what it cannot read. Who the participants are is the caller's business:
// the SFU knows them only by an opaque identity and an opaque label.

/** Key indexes the E2EE keyring holds (livekit-client's default). */
export const KEYRING_SIZE = 16

/** Frame keys the call sets by index; every participant shares them. */
export class FrameKeys extends BaseKeyProvider {
  constructor() {
    super({ sharedKey: true, ratchetWindowSize: 0, failureTolerance: -1, keyringSize: KEYRING_SIZE })
  }

  async set(key: Uint8Array, index: number): Promise<void> {
    const copy = new ArrayBuffer(key.byteLength)
    new Uint8Array(copy).set(key)
    this.onSetEncryptionKey(await createKeyMaterialFromBuffer(copy), undefined, index % KEYRING_SIZE)
  }
}

export interface SfuParticipant {
  /** The SFU identity: opaque to the SFU, meaningful to the call. */
  identity: string
  /** The opaque label the participant's token carried, if any. */
  label: string
  local: boolean
  audio: MediaStreamTrack | null
  video: MediaStreamTrack | null
  /** The screen this participant is sharing, beside the camera. */
  screen: MediaStreamTrack | null
  muted: boolean
  speaking: boolean
}

export interface SfuRoomHandlers {
  /** Someone joined, left, or changed what they send. */
  changed(): void
  /**
   * The room is gone: this participant was removed by a host, the room was
   * closed for everyone, or the connection dropped for good (or was left).
   */
  disconnected(why: 'removed' | 'closed' | 'other'): void
  /** A frame did not decrypt: the keys may be behind. */
  decryptionFailed(): void
  /** Bytes a participant sent to everyone in the room, outside the media. */
  data?(identity: string, payload: Uint8Array, topic: string): void
}

/** The topic of a call's chat messages. */
export const CHAT_TOPIC = 'kutup'
/** The topic of the hint that the meeting's hosts changed (no content). */
export const ROLES_TOPIC = 'kutup-roles'


export class SfuRoom {
  readonly keys = new FrameKeys()
  private readonly room: Room

  constructor(handlers: SfuRoomHandlers) {
    const room = new Room({
      adaptiveStream: true,
      dynacast: true,
      e2ee: {
        keyProvider: this.keys,
        worker: new Worker(new URL('livekit-client/e2ee-worker', import.meta.url), { type: 'module' }),
      },
    })
    this.room = room
    for (const event of [
      RoomEvent.ParticipantConnected,
      RoomEvent.ParticipantDisconnected,
      RoomEvent.ParticipantMetadataChanged,
      RoomEvent.TrackPublished,
      RoomEvent.TrackUnpublished,
      RoomEvent.TrackSubscribed,
      RoomEvent.TrackUnsubscribed,
      RoomEvent.TrackMuted,
      RoomEvent.TrackUnmuted,
      RoomEvent.LocalTrackPublished,
      RoomEvent.LocalTrackUnpublished,
      RoomEvent.ActiveSpeakersChanged,
    ]) {
      room.on(event, () => handlers.changed())
    }
    room.on(RoomEvent.DataReceived, (payload, participant, _kind, topic) => {
      if (participant && topic) handlers.data?.(participant.identity, payload, topic)
    })
    room.on(RoomEvent.Disconnected, (reason) =>
      handlers.disconnected(
        reason === DisconnectReason.PARTICIPANT_REMOVED ? 'removed' : reason === DisconnectReason.ROOM_DELETED ? 'closed' : 'other',
      ),
    )
    room.on(RoomEvent.EncryptionError, (error) => {
      console.warn('chat: a call frame did not decrypt', error)
      handlers.decryptionFailed()
    })
  }

  /** Join with the microphone on and, if asked, the camera. Set a key first. */
  async connect(url: string, token: string, withVideo: boolean): Promise<void> {
    await this.room.setE2EEEnabled(true)
    await this.room.connect(url, token)
    await this.room.localParticipant.setMicrophoneEnabled(true)
    if (withVideo) await this.room.localParticipant.setCameraEnabled(true)
  }

  async disconnect(): Promise<void> {
    await this.room.disconnect().catch(() => undefined)
  }

  get localIdentity(): string {
    return this.room.localParticipant.identity
  }

  /** Every identity in the room, this one included. */
  identities(): string[] {
    return [this.room.localParticipant.identity, ...this.room.remoteParticipants.keys()]
  }

  get remoteCount(): number {
    return this.room.remoteParticipants.size
  }

  get screenOn(): boolean {
    return this.room.localParticipant.isScreenShareEnabled
  }

  setMicrophone(on: boolean): Promise<unknown> {
    return this.room.localParticipant.setMicrophoneEnabled(on)
  }

  setCamera(on: boolean): Promise<unknown> {
    return this.room.localParticipant.setCameraEnabled(on)
  }

  /** The screen is one more published track, encrypted like the others. */
  setScreen(on: boolean): Promise<unknown> {
    return this.room.localParticipant.setScreenShareEnabled(on, { audio: false })
  }

  /**
   * Send bytes to everyone in the room, reliably. The SFU relays them as
   * they are: the caller seals what must stay private.
   */
  send(payload: Uint8Array, topic: string = CHAT_TOPIC): Promise<void> {
    const bytes = new Uint8Array(new ArrayBuffer(payload.byteLength))
    bytes.set(payload)
    return this.room.localParticipant.publishData(bytes, { reliable: true, topic })
  }

  participants(): SfuParticipant[] {
    const speaking = new Set(this.room.activeSpeakers.map((participant) => participant.identity))
    const describe = (participant: Participant, local: boolean): SfuParticipant => {
      const audio = participant.getTrackPublication(Track.Source.Microphone)
      const video = participant.getTrackPublication(Track.Source.Camera)
      const screen = participant.getTrackPublication(Track.Source.ScreenShare)
      return {
        identity: participant.identity,
        label: participant.metadata ?? '',
        local,
        audio: local ? null : (audio?.track?.mediaStreamTrack ?? null),
        video: video && !video.isMuted ? (video.track?.mediaStreamTrack ?? null) : null,
        screen: screen && !screen.isMuted ? (screen.track?.mediaStreamTrack ?? null) : null,
        muted: !audio || audio.isMuted,
        speaking: speaking.has(participant.identity),
      }
    }
    return [
      describe(this.room.localParticipant, true),
      ...[...this.room.remoteParticipants.values()].map((participant) => describe(participant, false)),
    ]
  }
}
