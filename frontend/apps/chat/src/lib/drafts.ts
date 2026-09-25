import { useSyncExternalStore } from 'react'
import type { MentionPick } from './mentions'

// Unsent text per conversation, kept in this browser across reloads (as
// Signal keeps drafts) and removed when the account signs out. The local
// chat history lives unencrypted in this browser's storage too, so a draft
// adds nothing a device thief could not already read.

export interface Draft {
  text: string
  picks: MentionPick[]
}

const PREFIX = 'kutup.chat.drafts.v1:'
const MAX_DRAFT_CHARS = 20_000
const listeners = new Set<() => void>()
let cache: { account: string; drafts: Record<string, Draft> } | null = null

function key(account: string): string {
  return `${PREFIX}${account}`
}

function load(account: string): Record<string, Draft> {
  if (cache?.account === account) return cache.drafts
  let drafts: Record<string, Draft> = {}
  try {
    const stored = window.localStorage.getItem(key(account))
    const parsed: unknown = stored ? JSON.parse(stored) : {}
    if (parsed && typeof parsed === 'object') drafts = parsed as Record<string, Draft>
  } catch {
    drafts = {}
  }
  cache = { account, drafts }
  return drafts
}

function store(account: string, drafts: Record<string, Draft>): void {
  cache = { account, drafts }
  try {
    if (Object.keys(drafts).length === 0) window.localStorage.removeItem(key(account))
    else window.localStorage.setItem(key(account), JSON.stringify(drafts))
  } catch {
    // Kept for this tab only.
  }
  for (const listener of listeners) listener()
}

export function getDraft(account: string, conversationKey: string): Draft | undefined {
  return load(account)[conversationKey]
}

/** Keep `draft` for a conversation; empty text removes it. */
export function setDraft(account: string, conversationKey: string, draft: Draft): void {
  const drafts = load(account)
  const text = draft.text.slice(0, MAX_DRAFT_CHARS)
  const current = drafts[conversationKey]
  if (!text.trim()) {
    if (!current) return
    const rest = { ...drafts }
    delete rest[conversationKey]
    store(account, rest)
    return
  }
  if (current?.text === text && JSON.stringify(current.picks) === JSON.stringify(draft.picks)) return
  store(account, { ...drafts, [conversationKey]: { text, picks: draft.picks } })
}

/** Forget every draft of an account (signing out). */
export function clearDrafts(account: string): void {
  store(account, {})
}

/** The draft texts of an account, by conversation key. */
export function useDrafts(account: string): Readonly<Record<string, Draft>> {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    () => load(account),
  )
}
