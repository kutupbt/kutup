import { useSyncExternalStore } from 'react'
import api from './client'

/**
 * Keyboard shortcuts in every app, on or off for the account (Proton's one
 * setting; docs/roadmap.md, "Keyboard shortcuts in every app"). On until
 * turned off. This browser keeps a copy for the first render; the account's
 * value comes with the UI preferences (`useAccountUiPreferences`).
 */

const KEY = 'kutup.shortcuts'
const PATH = '/account/ui-preferences'
const listeners = new Set<() => void>()

function stored(): boolean {
  try {
    return localStorage.getItem(KEY) !== 'off'
  } catch {
    return true
  }
}

let enabled = stored()

function publish(next: boolean): void {
  if (next === enabled) return
  enabled = next
  try {
    localStorage.setItem(KEY, next ? 'on' : 'off')
  } catch {
    // This browser keeps nothing; the account still has it.
  }
  for (const listener of listeners) listener()
}

/** Takes the account's value (null: never chosen, on). */
export function takeAccountShortcuts(value: boolean | null | undefined): void {
  publish(value !== false)
}

export function shortcutsEnabled(): boolean {
  return enabled
}

export function useShortcutsEnabled(): boolean {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    () => enabled,
  )
}

/** Turns shortcuts on or off for the account: every app and device. */
export async function setShortcutsEnabled(next: boolean): Promise<void> {
  const previous = enabled
  publish(next)
  try {
    // The theme and language are sent as the account has them.
    const { data } = await api.get<{ theme: string | null; language: string | null }>(PATH)
    await api.put(PATH, { theme: data.theme, language: data.language, shortcuts: next })
  } catch (error) {
    publish(previous)
    throw error
  }
}

/**
 * Whether a key press is the app's to take as a shortcut (Proton's
 * `isBusy`): not while typing, not with a dialog or menu open, not with a
 * modifier, and only with shortcuts on.
 */
export function isShortcutKey(event: KeyboardEvent): boolean {
  if (!enabled || event.defaultPrevented || event.altKey || event.ctrlKey || event.metaKey) return false
  const target = event.target
  if (target instanceof HTMLElement && (target.isContentEditable || target.closest('input, textarea, select, [role="dialog"], [role="alertdialog"], [role="menu"]'))) {
    return false
  }
  return !document.querySelector('[role="dialog"][data-state="open"], [role="alertdialog"][data-state="open"], [role="menu"][data-state="open"]')
}
