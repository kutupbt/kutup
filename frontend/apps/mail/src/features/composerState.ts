import { useSyncExternalStore } from 'react'
import type { Draft, MailMessage, OpenedMessage } from '@kutup/mail-core/api'

// What the composer is writing, shared by Compose, Reply, Reply all,
// Forward and opening a draft. One composer at a time, docked like Proton's.

export type ComposerTarget = (
  | { kind: 'new'; to?: string }
  | { kind: 'reply' | 'replyAll' | 'forward'; message: MailMessage; opened: OpenedMessage }
  | { kind: 'draft'; message: MailMessage; opened: OpenedMessage }
  // A send taken back (undo send): the draft as it was sent.
  | { kind: 'resume'; draft: Draft }
) & {
  /** Write as this shared mailbox (its group id) when allowed: replies from inside it. */
  fromGroup?: string
}

let target: ComposerTarget | null = null
/** Bumped on every open, so a new target starts a fresh composer. */
let generation = 0
const listeners = new Set<() => void>()

function set(next: ComposerTarget | null) {
  target = next
  generation += 1
  for (const listener of listeners) listener()
}

function snapshot() {
  return target
}

export function useComposer() {
  const current = useSyncExternalStore((listener) => {
    listeners.add(listener)
    return () => listeners.delete(listener)
  }, snapshot)
  return { target: current, generation, open: openComposer, close: closeComposer }
}

export function openComposer(next: ComposerTarget) {
  set(next)
}

/**
 * Closes the composer; with `of`, only if it is still that generation, so
 * a send that finishes after another composer opened leaves that one be.
 */
export function closeComposer(of?: number) {
  if (of !== undefined && of !== generation) return
  set(null)
}

/** The current generation, for a composer to close only itself later. */
export function composerGeneration() {
  return generation
}
