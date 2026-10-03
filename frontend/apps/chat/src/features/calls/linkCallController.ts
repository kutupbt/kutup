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

export interface LinkCallState {
  phase: 'connecting' | 'active' | 'ended'
  participants: LinkCallParticipant[]
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
    this.set({ phase: 'connecting', participants: [], muted: false, cameraOn: withVideo, screenOn: false })
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

  dispose(): void {
    void this.ended()
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
