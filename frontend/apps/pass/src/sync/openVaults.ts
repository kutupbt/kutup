// The vaults open in this tab, by Drive file id. A vault stays open while
// the person moves around the app, until they lock it or sign out.

import { useSyncExternalStore } from 'react'
import type { VaultFile } from '../drive/vaults'
import type { VaultKeyInput } from '../vault/types'
import { VaultSession, type SessionState } from './vaultSession'

const sessions = new Map<string, VaultSession>()
const opening = new Map<string, Promise<VaultSession>>()
const listeners = new Set<() => void>()
let version = 0

function changed() {
  version++
  for (const listener of listeners) listener()
}

function subscribe(listener: () => void) {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

/**
 * Opens a vault (once, however often it is asked); a wrong key throws.
 * `beforeShown` runs on the opened vault before it shows (keeping its key
 * with the sign-in): once the vault shows, a reload must not lose it. It
 * handles its own failures; the vault shows either way.
 */
export function openVault(
  vault: VaultFile,
  key: VaultKeyInput,
  userId: string,
  beforeShown?: (session: VaultSession) => Promise<void>,
): Promise<VaultSession> {
  const id = vault.file.id
  const open = sessions.get(id)
  if (open) return beforeShown ? beforeShown(open).then(() => open) : Promise.resolve(open)
  let pending = opening.get(id)
  if (!pending) {
    pending = VaultSession.open(vault.folder, vault.file, key, userId, vault.canEdit)
      .then(async (session) => {
        try {
          await beforeShown?.(session)
        } finally {
          sessions.set(id, session)
          changed()
        }
        return session
      })
      .finally(() => opening.delete(id))
    opening.set(id, pending)
    return pending
  }
  // Opening already for another caller: it shows when that one is done.
  return beforeShown ? pending.then(async (session) => (await beforeShown(session), session)) : pending
}

const LOCKED_KEY = 'kutup-pass-locked'

function lockedIds(): Set<string> {
  try {
    return new Set(JSON.parse(sessionStorage.getItem(LOCKED_KEY) ?? '[]') as string[])
  } catch {
    return new Set()
  }
}

function saveLocked(ids: Set<string>) {
  try {
    sessionStorage.setItem(LOCKED_KEY, JSON.stringify([...ids]))
  } catch {
    // This visit only.
  }
}

/**
 * Whether the vault was locked in this tab (by hand or after idling): it
 * then waits for a click before its kept key opens it again, also after a
 * reload of the tab.
 */
export function wasLocked(fileId: string): boolean {
  return lockedIds().has(fileId)
}

/** The vault was unlocked on purpose. */
export function clearLocked(fileId: string): void {
  const ids = lockedIds()
  if (ids.delete(fileId)) saveLocked(ids)
}

/** Locks a vault: saves what is waiting (it stays in the outbox if that fails) and forgets it here. */
export async function lockVault(fileId: string): Promise<void> {
  const session = sessions.get(fileId)
  if (!session) return
  const ids = lockedIds()
  ids.add(fileId)
  saveLocked(ids)
  try {
    await session.save()
  } catch {
    // Kept in the outbox; saved the next time the vault opens.
  }
  sessions.delete(fileId)
  changed()
  await session.close()
}

export async function lockAll(): Promise<void> {
  freshKeys.clear()
  await Promise.all([...sessions.keys()].map(lockVault))
}

export function openVaultIds(): string[] {
  return [...sessions.keys()]
}

/** The open session of a vault, if it is open. */
export function useVaultSession(fileId: string | undefined): VaultSession | null {
  useSyncExternalStore(subscribe, () => version)
  return fileId ? (sessions.get(fileId) ?? null) : null
}

/** Re-renders with every change of the vault's state. */
export function useSessionState(session: VaultSession | null): SessionState | null {
  return useSyncExternalStore(
    (listener) => (session ? session.subscribe(listener) : () => {}),
    () => session?.getState() ?? null,
  )
}

/**
 * Keys typed this visit for vaults just made, so the new vault opens without
 * asking again; each is dropped once its vault opens, and all on lock.
 */
export const freshKeys = new Map<string, VaultKeyInput>()
