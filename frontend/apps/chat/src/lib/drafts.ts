import { useSyncExternalStore } from 'react'
import type { SealedStorage } from '@kutup/chat-core/sealedStorage'
import type { MentionPick } from './mentions'
import { activeSealedStorage, subscribeSealed } from '../state/sealedState'

// Unsent text per conversation, kept in this browser across reloads (as
// Signal keeps drafts), sealed for the account like the chat store, and
// removed when the account signs out.

export interface Draft {
  text: string
  picks: MentionPick[]
}

type Drafts = Record<string, Draft>

const NAME = 'drafts'
const MAX_DRAFT_CHARS = 20_000
const listeners = new Set<() => void>()
let cache: { storage: SealedStorage | null; drafts: Drafts } | null = null

function load(): Drafts {
  const storage = activeSealedStorage()
  if (cache?.storage !== storage) {
    const stored = storage?.read<unknown>(NAME)
    cache = { storage, drafts: stored && typeof stored === 'object' ? (stored as Drafts) : {} }
  }
  return cache.drafts
}

function store(drafts: Drafts): void {
  const storage = activeSealedStorage()
  cache = { storage, drafts }
  storage?.write(NAME, Object.keys(drafts).length === 0 ? undefined : drafts)
  for (const listener of listeners) listener()
}

export function getDraft(conversationKey: string): Draft | undefined {
  return load()[conversationKey]
}

/** Keep `draft` for a conversation; empty text removes it. */
export function setDraft(conversationKey: string, draft: Draft): void {
  const drafts = load()
  const text = draft.text.slice(0, MAX_DRAFT_CHARS)
  const current = drafts[conversationKey]
  if (!text.trim()) {
    if (!current) return
    const rest = { ...drafts }
    delete rest[conversationKey]
    store(rest)
    return
  }
  if (current?.text === text && JSON.stringify(current.picks) === JSON.stringify(draft.picks)) return
  store({ ...drafts, [conversationKey]: { text, picks: draft.picks } })
}

/** Forget every draft of the account (signing out). */
export function clearDrafts(): void {
  store({})
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener)
  const unsubscribe = subscribeSealed(NAME, () => {
    cache = null
    listener()
  })
  return () => {
    listeners.delete(listener)
    unsubscribe()
  }
}

/** The account's draft texts, by conversation key. */
export function useDrafts(): Readonly<Drafts> {
  return useSyncExternalStore(subscribe, load)
}
