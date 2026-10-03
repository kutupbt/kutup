// Several tabs of the chat may be open; one of them notifies (so a message
// sounds once), and none does for a conversation a focused tab shows.
//
// - The notifier is whichever tab holds a Web Lock for the account; when it
//   closes, another tab takes over.
// - Every tab tells the others, over a BroadcastChannel, whether it has
//   focus and which conversation it shows.

interface FocusState {
  focused: boolean
  key: string | null
  at: number
}

const TAB_ID = Math.random().toString(36).slice(2)
/** A tab not heard from for this long is taken to be gone. */
const STALE_MS = 60_000

export class NotifyTabs {
  private notifier = false
  private readonly channel: BroadcastChannel
  private readonly tabs = new Map<string, FocusState>()
  private readonly release: () => void
  private current: FocusState = { focused: false, key: null, at: 0 }
  private readonly heartbeat: ReturnType<typeof setInterval>

  constructor(account: string) {
    let release = () => {}
    const held = new Promise<void>((resolve) => {
      release = resolve
    })
    this.release = release
    void navigator.locks
      ?.request(`kutup-chat-notifier:${account}`, () => {
        this.notifier = true
        return held
      })
      .catch(() => undefined)
    this.channel = new BroadcastChannel(`kutup-chat-focus:${account}`)
    this.channel.onmessage = (event: MessageEvent<{ tab?: unknown; state?: FocusState }>) => {
      const { tab, state } = event.data ?? {}
      if (typeof tab === 'string' && state && typeof state.focused === 'boolean') {
        this.tabs.set(tab, { ...state, at: Date.now() })
      }
    }
    this.heartbeat = setInterval(() => this.announce(), STALE_MS / 3)
  }

  /** This tab shows notifications. */
  get isNotifier(): boolean {
    return this.notifier
  }

  /** Tell the other tabs what this one shows now. */
  update(focused: boolean, key: string | null): void {
    this.current = { focused, key, at: Date.now() }
    this.announce()
  }

  private announce(): void {
    this.current.at = Date.now()
    this.channel.postMessage({ tab: TAB_ID, state: this.current })
  }

  /** The conversation a focused tab (this one or another) shows, if any. */
  focusedKey(): string | null {
    if (this.current.focused) return this.current.key
    const now = Date.now()
    for (const state of this.tabs.values()) {
      if (state.focused && now - state.at < STALE_MS) return state.key
    }
    return null
  }

  /** Some tab of the chat has focus. */
  anyFocused(): boolean {
    if (this.current.focused) return true
    const now = Date.now()
    return [...this.tabs.values()].some((state) => state.focused && now - state.at < STALE_MS)
  }

  dispose(): void {
    clearInterval(this.heartbeat)
    this.update(false, null)
    this.channel.close()
    this.release()
  }
}
