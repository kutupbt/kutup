import type { ChatHistoryEntry, ConversationId } from './types'

/**
 * The live window of Chat's history (`docs/research/16-browser-storage-architecture.md`,
 * Phase 2b): each conversation's newest entries (and those still unread),
 * its disappearing timer, and the account's own controls, read from the
 * core's per-conversation timelines instead of the whole history. After a
 * change made here, only the conversations it touched are read again; after
 * one from another tab, or when that is not known, all of them.
 *
 * Older pages of a conversation are not part of the window: they are read
 * for the conversation on screen only (`page`), so nothing that acts on new
 * arrivals (notifications, receipts) ever sees them as new.
 */

/** Entries per conversation kept beyond the unread ones. */
export const RECENT_ENTRIES = 30

export interface ConversationSummary {
  /** The app's key for the conversation (`conversationKey`). */
  key: string
  conversation: ConversationId
  latestMs: number
  /** Incoming messages newer than the read position given when read. */
  unread: number
  /** Newest first. */
  recent: ChatHistoryEntry[]
  /** The newest disappearing-timer change, when older than `recent`. */
  timer: ChatHistoryEntry | null
}

/** What the core returns, before addresses are completed. */
export interface CoreConversationSummary {
  key: string
  conversation: ConversationId
  latestMs: number
  unread: number
  recent: ChatHistoryEntry[]
  timer?: ChatHistoryEntry | null
}

export interface CorePage {
  entries: ChatHistoryEntry[]
  before?: string | null
}

/** The core calls the window needs, each run under the engine lock. */
export interface LiveTimelineCore {
  /** Writes committed so far, and the conversations touched since `mark` (null: unknown). */
  changes(mark: number): Promise<{ commits: number; keys: string[] | null }>
  accountControls(): Promise<ChatHistoryEntry[]>
  summaries(readThrough: Record<string, number>, recent: number, keys?: string[]): Promise<CoreConversationSummary[]>
  page(key: string, before: string | undefined, limit: number): Promise<CorePage>
}

export interface LiveWindow {
  summaries: ConversationSummary[]
  controls: ChatHistoryEntry[]
}

export class LiveTimeline {
  private mark = -1
  private everything = true
  private controls: ChatHistoryEntry[] = []
  /** By the core's key. */
  private readonly summaries = new Map<string, ConversationSummary>()
  /** App key → core key. */
  private readonly coreKeys = new Map<string, string>()

  constructor(
    private readonly core: LiveTimelineCore,
    /** Completes an entry's addresses (the home server of local accounts). */
    private readonly normalize: (entry: ChatHistoryEntry) => ChatHistoryEntry,
    /** The app's key for a conversation, from the core's form. */
    private readonly appKey: (conversation: ConversationId) => { key: string; conversation: ConversationId },
    /** The app key of this account's Note to Self, where its controls travel. */
    private readonly selfKey: string,
  ) {}

  /** Something changed that this tab's journal does not know (another tab). */
  invalidateAll(): void {
    this.everything = true
  }

  /**
   * The window, brought up to date. `readThroughFor` gives the read
   * positions (by app key) from the account's controls.
   */
  async refresh(
    readThroughFor: (controls: readonly ChatHistoryEntry[]) => Readonly<Record<string, number>>,
  ): Promise<LiveWindow> {
    const everything = this.everything || this.mark < 0
    const { commits, keys } = await this.core.changes(Math.max(this.mark, 0))
    const reloadAll = everything || keys === null
    const touched = reloadAll ? null : keys
    if (reloadAll || touched!.includes(this.coreKeys.get(this.selfKey) ?? '')) {
      this.controls = (await this.core.accountControls()).map(this.normalize)
    }
    if (reloadAll || touched!.length > 0) {
      const appReadThrough = readThroughFor(this.controls)
      const readThrough: Record<string, number> = {}
      for (const [appKey, at] of Object.entries(appReadThrough)) {
        const coreKey = this.coreKeys.get(appKey)
        if (coreKey) readThrough[coreKey] = at
      }
      const fresh = await this.core.summaries(readThrough, RECENT_ENTRIES, touched ?? undefined)
      if (reloadAll) {
        this.summaries.clear()
        this.coreKeys.clear()
      } else {
        for (const key of touched!) this.summaries.delete(key)
      }
      for (const summary of fresh) {
        const { key, conversation } = this.appKey(summary.conversation)
        this.coreKeys.set(key, summary.key)
        this.summaries.set(summary.key, {
          key,
          conversation,
          latestMs: summary.latestMs,
          unread: summary.unread,
          recent: summary.recent.map(this.normalize),
          timer: summary.timer ? this.normalize(summary.timer) : null,
        })
      }
    }
    this.mark = commits
    this.everything = false
    return { summaries: [...this.summaries.values()], controls: this.controls }
  }

  /**
   * One page of a conversation (by app key), newest first, older than
   * `before`; `before` in the result continues it, absent at the start.
   */
  async page(key: string, before: string | undefined, limit: number): Promise<{ entries: ChatHistoryEntry[]; before?: string }> {
    const coreKey = this.coreKeys.get(key)
    if (!coreKey) return { entries: [] }
    const page = await this.core.page(coreKey, before, limit)
    return { entries: page.entries.map(this.normalize), before: page.before ?? undefined }
  }
}

/** The window as one history, oldest first, each entry once. */
export function windowHistory(window: LiveWindow, extra: readonly ChatHistoryEntry[] = []): ChatHistoryEntry[] {
  const byId = new Map<string, ChatHistoryEntry>()
  const add = (entry: ChatHistoryEntry) => {
    if (!byId.has(entry.id)) byId.set(entry.id, entry)
  }
  for (const summary of window.summaries) {
    for (const entry of summary.recent) add(entry)
    if (summary.timer) add(summary.timer)
  }
  for (const entry of window.controls) add(entry)
  for (const entry of extra) add(entry)
  return [...byId.values()].sort((left, right) => left.timestampMs - right.timestampMs || left.id.localeCompare(right.id))
}
