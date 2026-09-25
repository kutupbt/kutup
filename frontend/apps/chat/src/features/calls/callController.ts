import { canonicalAccountAddress, parseAccountAddress } from '@kutup/chat-core/identity'
import type { ChatService } from '@kutup/chat-core/service'
import type {
  AccountAddress,
  ChatCallEvent,
  ChatCallLog,
  ChatCallMedia,
  ChatCallOutcome,
  ChatCallSignal,
  ChatCallSignalKind,
  ChatIceCandidate,
} from '@kutup/chat-core/types'

// One 1:1 call at a time, over WebRTC, with its signals end-to-end
// encrypted through the Direct session (docs/chat-calls.md).
//
// - Incoming calls ring in one tab per account: the one holding the "call
//   desk" lock. Any tab can place a call; a lock held during any call makes
//   the desk answer "busy" to other callers.
// - ICE candidates go out in small batches (each send fetches the peer's keys).
// - The video line is always negotiated both ways, so turning the camera on
//   during a call is a track swap, not a renegotiation.
// - The device that took part writes the call into the timeline when it ends.

export type CallPhase = 'incoming' | 'outgoing' | 'connecting' | 'active' | 'ended'

export interface CallState {
  callId: string
  /** Canonical address of the other person. */
  peer: string
  media: ChatCallMedia
  incoming: boolean
  phase: CallPhase
  startedAtMs: number
  connectedAtMs?: number
  muted: boolean
  cameraOn: boolean
  localStream: MediaStream | null
  remoteStream: MediaStream | null
  /** Why it ended, for the last screen. */
  endReason?: 'hungUp' | 'declined' | 'busy' | 'unanswered' | 'failed' | 'missed' | 'elsewhere'
}

/** Ring this long before giving up. */
const RING_MS = 60_000
/** An offer older than this is a call already over. */
const STALE_OFFER_MS = 45_000
/** A dropped connection gets this long to come back. */
const RECONNECT_MS = 10_000
const ICE_BATCH_MS = 250
/** How long the "call ended" screen stays. */
const ENDED_SCREEN_MS = 2_000

export interface CallOptions {
  /** Hide this browser's address: send media only through the TURN relay. */
  alwaysRelay: boolean
}

type Listener = () => void

export class CallController {
  private state: CallState | null = null
  private readonly listeners = new Set<Listener>()
  private pc: RTCPeerConnection | null = null
  private peerAddress: AccountAddress | null = null
  private callerDeviceId = 0
  private calleeDeviceId: number | undefined
  private remoteOffer: string | null = null
  private pendingRemote: ChatIceCandidate[] = []
  private pendingLocal: ChatIceCandidate[] = []
  private iceTimer: ReturnType<typeof setTimeout> | null = null
  private ringTimer: ReturnType<typeof setTimeout> | null = null
  private dropTimer: ReturnType<typeof setTimeout> | null = null
  private clearTimer: ReturnType<typeof setTimeout> | null = null
  private releaseInCall: (() => void) | null = null
  private releaseDesk: (() => void) | null = null
  private isDesk = false
  private readonly unsubscribe: () => void

  constructor(
    private readonly service: ChatService,
    private readonly account: string,
    private readonly options: () => CallOptions,
  ) {
    this.unsubscribe = service.subscribeCalls((event) => void this.handle(event))
    const held = new Promise<void>((resolve) => {
      this.releaseDesk = resolve
    })
    void navigator.locks
      ?.request(`kutup-chat-call-desk:${account}`, () => {
        this.isDesk = true
        return held
      })
      .catch(() => undefined)
  }

  // --- State for the screen -----------------------------------------------

  get current(): CallState | null {
    return this.state
  }

  /** This tab rings for incoming calls (one tab per account does). */
  get ringsHere(): boolean {
    return this.isDesk
  }

  subscribe(listener: Listener): () => void {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  private set(patch: Partial<CallState> | null): void {
    this.state = patch === null ? null : ({ ...this.state, ...patch } as CallState)
    for (const listener of this.listeners) listener()
  }

  // --- Placing and answering ----------------------------------------------

  async start(peer: AccountAddress, media: ChatCallMedia): Promise<void> {
    if (this.state && this.state.phase !== 'ended') throw new Error('already in a call')
    this.reset()
    const callId = crypto.randomUUID()
    this.peerAddress = peer
    this.callerDeviceId = this.service.deviceId
    this.calleeDeviceId = undefined
    await this.holdInCall()
    this.set({
      callId,
      peer: canonicalAccountAddress(peer),
      media,
      incoming: false,
      phase: 'outgoing',
      startedAtMs: Date.now(),
      muted: false,
      cameraOn: media === 'video',
      localStream: null,
      remoteStream: null,
    })
    try {
      const local = await navigator.mediaDevices.getUserMedia({ audio: true, video: media === 'video' })
      if (this.state?.callId !== callId) {
        stopStream(local)
        return
      }
      this.set({ localStream: local })
      const pc = await this.connection()
      const audio = local.getAudioTracks()[0]
      const video = local.getVideoTracks()[0]
      pc.addTransceiver(audio ?? 'audio', { direction: 'sendrecv', streams: [local] })
      pc.addTransceiver(video ?? 'video', { direction: 'sendrecv', streams: [local] })
      const offer = await pc.createOffer()
      await pc.setLocalDescription(offer)
      await this.send({ type: 'offer', media, sdp: offer.sdp ?? '' })
      this.ringTimer = setTimeout(() => void this.end('unanswered', { type: 'hangup', reason: 'unanswered' }), RING_MS)
    } catch (error) {
      console.warn('chat: could not start a call', error)
      await this.end('failed', { type: 'hangup', reason: 'failed' })
      throw error
    }
  }

  async accept(withVideo: boolean): Promise<void> {
    const state = this.state
    if (!state || state.phase !== 'incoming' || !this.remoteOffer) return
    this.clearRing()
    await this.holdInCall()
    this.calleeDeviceId = this.service.deviceId
    this.set({ phase: 'connecting', cameraOn: withVideo })
    try {
      const local = await navigator.mediaDevices.getUserMedia({ audio: true, video: withVideo })
      if (this.state?.callId !== state.callId) {
        stopStream(local)
        return
      }
      this.set({ localStream: local })
      const pc = await this.connection()
      await pc.setRemoteDescription({ type: 'offer', sdp: this.remoteOffer })
      for (const transceiver of pc.getTransceivers()) {
        const kind = transceiver.receiver.track.kind
        transceiver.direction = 'sendrecv'
        const track = kind === 'audio' ? local.getAudioTracks()[0] : local.getVideoTracks()[0]
        if (track) {
          await transceiver.sender.replaceTrack(track)
          transceiver.sender.setStreams?.(local)
        }
      }
      await this.flushRemoteCandidates()
      const answer = await pc.createAnswer()
      await pc.setLocalDescription(answer)
      await this.send({ type: 'answer', sdp: answer.sdp ?? '' })
    } catch (error) {
      console.warn('chat: could not answer a call', error)
      await this.end('failed', { type: 'hangup', reason: 'failed' })
    }
  }

  async decline(): Promise<void> {
    if (this.state?.phase !== 'incoming') return
    await this.end('declined', { type: 'hangup', reason: 'declined' })
  }

  async hangUp(): Promise<void> {
    if (!this.state || this.state.phase === 'ended') return
    if (this.state.phase === 'incoming') return this.decline()
    await this.end('hungUp', { type: 'hangup', reason: 'normal' })
  }

  toggleMute(): void {
    const state = this.state
    if (!state?.localStream) return
    const muted = !state.muted
    for (const track of state.localStream.getAudioTracks()) track.enabled = !muted
    this.set({ muted })
  }

  async toggleCamera(): Promise<void> {
    const state = this.state
    const pc = this.pc
    if (!state?.localStream || !pc) return
    const sender = pc.getTransceivers().find((transceiver) => transceiver.receiver.track.kind === 'video')?.sender
    if (!sender) return
    if (state.cameraOn) {
      for (const track of state.localStream.getVideoTracks()) {
        track.stop()
        state.localStream.removeTrack(track)
      }
      await sender.replaceTrack(null)
      this.set({ cameraOn: false, localStream: new MediaStream(state.localStream.getTracks()) })
      return
    }
    const camera = await navigator.mediaDevices.getUserMedia({ video: true })
    const track = camera.getVideoTracks()[0]
    if (!track) return
    await sender.replaceTrack(track)
    this.set({ cameraOn: true, localStream: new MediaStream([...state.localStream.getTracks(), track]) })
  }

  dispose(): void {
    if (this.state && this.state.phase !== 'ended') void this.hangUp()
    this.unsubscribe()
    this.releaseDesk?.()
  }

  // --- Signals --------------------------------------------------------------

  private async handle(event: ChatCallEvent): Promise<void> {
    const { call } = event
    const state = this.state
    const mine = state?.callId === call.callId && state.phase !== 'ended'
    if (call.signal.type === 'offer') {
      await this.handleOffer(event, call.signal.media, call.signal.sdp)
      return
    }
    if (!mine || event.peer !== state.peer) return
    if (state.incoming) {
      // From the caller. Once a device answered, only it takes part.
      if (call.callerDeviceId !== event.senderDeviceId) return
      if (call.signal.type === 'hangup') {
        const elsewhere = call.signal.reason === 'answeredElsewhere' || call.signal.reason === 'declinedElsewhere'
        if (elsewhere && call.calleeDeviceId !== this.service.deviceId) {
          await this.end('elsewhere', null)
          return
        }
        if (!elsewhere) await this.end(state.phase === 'incoming' ? 'missed' : 'hungUp', null)
        return
      }
      if (call.calleeDeviceId !== undefined && call.calleeDeviceId !== this.service.deviceId) return
      if (call.signal.type === 'ice') await this.addRemoteCandidates(call.signal.candidates)
      return
    }
    // Outgoing: replies must be for this device.
    if (call.callerDeviceId !== this.service.deviceId) return
    if (this.calleeDeviceId !== undefined && event.senderDeviceId !== this.calleeDeviceId) return
    switch (call.signal.type) {
      case 'answer': {
        if (this.calleeDeviceId !== undefined || !this.pc) return
        this.calleeDeviceId = event.senderDeviceId
        this.clearRing()
        this.set({ phase: 'connecting' })
        await this.pc.setRemoteDescription({ type: 'answer', sdp: call.signal.sdp })
        await this.flushRemoteCandidates()
        // The callee's other devices stop ringing.
        await this.send({ type: 'hangup', reason: 'answeredElsewhere' })
        return
      }
      case 'ice':
        await this.addRemoteCandidates(call.signal.candidates)
        return
      case 'busy':
        if (this.calleeDeviceId === undefined) await this.end('busy', null)
        return
      case 'hangup':
        if (call.signal.reason === 'declined' && this.calleeDeviceId === undefined) {
          this.calleeDeviceId = event.senderDeviceId
          await this.send({ type: 'hangup', reason: 'declinedElsewhere' })
          await this.end('declined', null)
          return
        }
        await this.end(call.signal.reason === 'failed' ? 'failed' : 'hungUp', null)
    }
  }

  private async handleOffer(event: ChatCallEvent, media: ChatCallMedia, sdp: string): Promise<void> {
    const sentAt = Date.parse(event.sentAt)
    const stale = !Number.isFinite(sentAt) || Date.now() - sentAt > STALE_OFFER_MS
    if (this.state && this.state.phase !== 'ended') {
      // Busy: only the tab in the call says so.
      if (this.state.callId !== event.call.callId && !stale) {
        await this.reply(event, { type: 'busy' })
      }
      return
    }
    if (!this.isDesk) return
    if (await this.anotherTabInCall()) {
      if (!stale) await this.reply(event, { type: 'busy' })
      return
    }
    const peer = parseAccountAddress(event.peer)
    if (!peer) return
    if (stale) {
      await this.record(peer, event.call.callId, true, media, 'missed', sentAt || Date.now())
      return
    }
    this.reset()
    this.peerAddress = peer
    this.callerDeviceId = event.call.callerDeviceId
    this.calleeDeviceId = undefined
    this.remoteOffer = sdp
    this.set({
      callId: event.call.callId,
      peer: event.peer,
      media,
      incoming: true,
      phase: 'incoming',
      startedAtMs: sentAt,
      muted: false,
      cameraOn: false,
      localStream: null,
      remoteStream: null,
    })
    this.ringTimer = setTimeout(() => void this.end('missed', null), RING_MS)
  }

  private reply(event: ChatCallEvent, signal: ChatCallSignalKind): Promise<void> {
    const peer = parseAccountAddress(event.peer)
    if (!peer) return Promise.resolve()
    return this.service
      .sendCallSignal(peer, {
        callId: event.call.callId,
        callerDeviceId: event.call.callerDeviceId,
        calleeDeviceId: this.service.deviceId,
        signal,
      })
      .catch((error: unknown) => console.warn('chat: could not answer busy', error))
  }

  private async send(signal: ChatCallSignalKind): Promise<void> {
    const state = this.state
    if (!state || !this.peerAddress) return
    const call: ChatCallSignal = {
      callId: state.callId,
      callerDeviceId: this.callerDeviceId,
      ...(this.calleeDeviceId !== undefined ? { calleeDeviceId: this.calleeDeviceId } : {}),
      signal,
    }
    await this.service.sendCallSignal(this.peerAddress, call)
  }

  // --- WebRTC ----------------------------------------------------------------

  private async connection(): Promise<RTCPeerConnection> {
    const servers = await this.service.callServers()
    const relay = this.options().alwaysRelay && servers.relay
    const pc = new RTCPeerConnection({
      iceServers: servers.iceServers,
      iceTransportPolicy: relay ? 'relay' : 'all',
    })
    this.pc = pc
    const remote = new MediaStream()
    this.set({ remoteStream: remote })
    pc.ontrack = (event) => {
      if (!remote.getTracks().includes(event.track)) remote.addTrack(event.track)
      this.set({ remoteStream: new MediaStream(remote.getTracks()) })
    }
    pc.onicecandidate = (event) => {
      if (!event.candidate || !event.candidate.candidate) return
      this.pendingLocal.push({
        candidate: event.candidate.candidate,
        ...(event.candidate.sdpMid ? { sdpMid: event.candidate.sdpMid } : {}),
        ...(event.candidate.sdpMLineIndex !== null ? { sdpMLineIndex: event.candidate.sdpMLineIndex } : {}),
      })
      this.iceTimer ??= setTimeout(() => void this.flushLocalCandidates(), ICE_BATCH_MS)
    }
    pc.onconnectionstatechange = () => {
      const state = pc.connectionState
      if (state === 'connected') {
        if (this.dropTimer) clearTimeout(this.dropTimer)
        this.dropTimer = null
        if (this.state?.phase === 'connecting') this.set({ phase: 'active', connectedAtMs: Date.now() })
      } else if (state === 'failed') {
        void this.end('failed', { type: 'hangup', reason: 'failed' })
      } else if (state === 'disconnected') {
        this.dropTimer ??= setTimeout(() => void this.end('failed', { type: 'hangup', reason: 'failed' }), RECONNECT_MS)
      }
    }
    return pc
  }

  private async flushLocalCandidates(): Promise<void> {
    this.iceTimer = null
    // The caller holds its candidates until it knows which device answered.
    if (!this.state?.incoming && this.calleeDeviceId === undefined && this.state?.phase === 'outgoing') {
      this.iceTimer = setTimeout(() => void this.flushLocalCandidates(), ICE_BATCH_MS)
      return
    }
    while (this.pendingLocal.length > 0) {
      const batch = this.pendingLocal.splice(0, 32)
      await this.send({ type: 'ice', candidates: batch }).catch((error: unknown) =>
        console.warn('chat: could not send ICE candidates', error))
    }
  }

  private async addRemoteCandidates(candidates: ChatIceCandidate[]): Promise<void> {
    if (!this.pc?.remoteDescription) {
      this.pendingRemote.push(...candidates)
      return
    }
    for (const candidate of candidates) {
      await this.pc.addIceCandidate(candidate).catch((error: unknown) =>
        console.warn('chat: a remote ICE candidate was refused', error))
    }
  }

  private async flushRemoteCandidates(): Promise<void> {
    const pending = this.pendingRemote.splice(0)
    await this.addRemoteCandidates(pending)
  }

  // --- Ending ----------------------------------------------------------------

  private async end(reason: NonNullable<CallState['endReason']>, signal: ChatCallSignalKind | null): Promise<void> {
    const state = this.state
    if (!state || state.phase === 'ended') return
    const peer = this.peerAddress
    const answered = state.connectedAtMs !== undefined
    this.set({ phase: 'ended', endReason: reason })
    if (signal) await this.send(signal).catch((error: unknown) => console.warn('chat: could not send a hang-up', error))
    this.teardown()
    const outcome = outcomeOf(state.incoming, reason, answered)
    if (peer && outcome) {
      await this.record(
        peer,
        state.callId,
        state.incoming,
        state.media,
        outcome,
        state.startedAtMs,
        answered ? Math.max(0, Math.round((Date.now() - state.connectedAtMs!) / 1000)) : undefined,
      )
    }
    this.clearTimer = setTimeout(() => {
      if (this.state?.callId === state.callId && this.state.phase === 'ended') this.set(null)
    }, ENDED_SCREEN_MS)
  }

  private async record(
    peer: AccountAddress,
    callId: string,
    incoming: boolean,
    media: ChatCallMedia,
    outcome: ChatCallOutcome,
    startedAtMs: number,
    durationSeconds?: number,
  ): Promise<void> {
    const body: ChatCallLog = {
      callId,
      incoming,
      media,
      outcome,
      startedAtMs,
      ...(outcome === 'answered' ? { durationSeconds: durationSeconds ?? 0 } : {}),
    }
    await this.service.recordCallLog(peer, body).catch((error: unknown) =>
      console.warn('chat: could not record a call', error))
  }

  private teardown(): void {
    this.clearRing()
    if (this.iceTimer) clearTimeout(this.iceTimer)
    if (this.dropTimer) clearTimeout(this.dropTimer)
    this.iceTimer = null
    this.dropTimer = null
    this.pc?.close()
    this.pc = null
    if (this.state?.localStream) stopStream(this.state.localStream)
    this.pendingLocal = []
    this.pendingRemote = []
    this.remoteOffer = null
    this.releaseInCall?.()
    this.releaseInCall = null
  }

  private reset(): void {
    if (this.clearTimer) clearTimeout(this.clearTimer)
    this.clearTimer = null
    this.teardown()
    this.state = null
  }

  private clearRing(): void {
    if (this.ringTimer) clearTimeout(this.ringTimer)
    this.ringTimer = null
  }

  private async holdInCall(): Promise<void> {
    if (this.releaseInCall) return
    await new Promise<void>((granted) => {
      const held = new Promise<void>((resolve) => {
        this.releaseInCall = resolve
      })
      void navigator.locks
        ?.request(`kutup-chat-in-call:${this.account}`, { ifAvailable: true }, (lock) => {
          granted()
          return lock ? held : undefined
        })
        .catch(() => granted())
      if (!navigator.locks) granted()
    })
  }

  private async anotherTabInCall(): Promise<boolean> {
    const snapshot = await navigator.locks?.query()
    return snapshot?.held?.some((lock) => lock.name === `kutup-chat-in-call:${this.account}`) ?? false
  }
}

/** What goes into the timeline for how a call ended; nothing when another device took it. */
export function outcomeOf(
  incoming: boolean,
  reason: NonNullable<CallState['endReason']>,
  answered: boolean,
): ChatCallOutcome | null {
  if (reason === 'elsewhere') return null
  if (answered) return 'answered'
  switch (reason) {
    case 'declined':
      return 'declined'
    case 'busy':
      return 'busy'
    case 'failed':
      return 'failed'
    case 'missed':
      return 'missed'
    default:
      return incoming ? 'missed' : 'unanswered'
  }
}

function stopStream(stream: MediaStream): void {
  for (const track of stream.getTracks()) track.stop()
}

