import { useSyncExternalStore } from 'react'
import type { CallController, CallState } from './callController'
import type { GroupCallController, GroupCallState } from './groupCallController'

// The chat's one call controller, set while the chat is open, so any
// component (the conversation header, the call screen) can reach it.

let controller: CallController | null = null
const listeners = new Set<() => void>()
let unsubscribe: (() => void) | null = null

function notify(): void {
  for (const listener of listeners) listener()
}

export function setCallController(next: CallController | null): void {
  unsubscribe?.()
  unsubscribe = next ? next.subscribe(notify) : null
  controller = next
  notify()
}

export function callController(): CallController | null {
  return controller
}

export function useCall(): CallState | null {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    () => controller?.current ?? null,
  )
}

// The group call controller, alike.

let groupController: GroupCallController | null = null
const groupListeners = new Set<() => void>()
let groupUnsubscribe: (() => void) | null = null

function notifyGroup(): void {
  for (const listener of groupListeners) listener()
}

export function setGroupCallController(next: GroupCallController | null): void {
  groupUnsubscribe?.()
  groupUnsubscribe = next ? next.subscribe(notifyGroup) : null
  groupController = next
  notifyGroup()
}

export function groupCallController(): GroupCallController | null {
  return groupController
}

export function useGroupCall(): GroupCallState | null {
  return useSyncExternalStore(
    (listener) => {
      groupListeners.add(listener)
      return () => groupListeners.delete(listener)
    },
    () => groupController?.current ?? null,
  )
}
