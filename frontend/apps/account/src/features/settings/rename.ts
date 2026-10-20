// A new username (docs/plans/username-renames.md). The account keeps
// everything but its name: the client signs the rename with the account
// authority and, for a name that has none, makes the new address's first
// mail key (its Drive key binding names its permanent id, so it stays,
// docs/plans/account-ids.md); the server
// moves the names in one transaction. The old name is held for the account:
// it receives (only) for a while, then is freed.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import { toBase64 } from '@kutup/crypto/base64'
import { foldAddress, signAccountRename, type AccountRenameV1 } from '@kutup/crypto/accountRename'
import { firstAddressKey, ownAddressState, type FirstAddressKey } from '@kutup/mail-core/addressKey'
import { loadServerSettings } from '@kutup/session/apps'
import api from '@kutup/session/client'
import { recheckAccount, type MeResponse } from '@kutup/session/profile'
import { accountGrant, type OneUseSecret } from '@kutup/session/reauth'
import { getSession } from '@kutup/session/store'
import { meKey, securityEventsKey } from './api'

/** A username's form: as registration and the server take it. */
export const USERNAME = /^[a-z0-9_-]{3,32}$/

export type NameCheck =
  | {
      available: true
      /** One of the account's own held names: taken back only as it was spelled (`spelling`). */
      takeBack?: boolean
      needsKey: boolean
      spelling?: string
    }
  | { available: false; reason: 'taken' | 'held' | 'reserved' | 'invalid' | (string & {}) }

/** Whether the account could rename to `name` (`GET /api/user/rename/check`). */
export async function checkName(name: string, signal?: AbortSignal): Promise<NameCheck> {
  return (await api.get<NameCheck>('/user/rename/check', { params: { name }, signal })).data
}

/** How long an old name receives and is held: the server's settings now. */
export interface NameWindows {
  oldAddressReceiveDays: number
  nameHoldDays: number
}

export function useNameWindows() {
  return useQuery({
    queryKey: ['name-windows'],
    queryFn: async (): Promise<NameWindows> => {
      const settings = await loadServerSettings<Partial<NameWindows>>()
      if (typeof settings.oldAddressReceiveDays !== 'number' || typeof settings.nameHoldDays !== 'number') {
        throw new Error('the server did not say how long old names are kept')
      }
      return { oldAddressReceiveDays: settings.oldAddressReceiveDays, nameHoldDays: settings.nameHoldDays }
    },
    staleTime: Infinity,
  })
}

export interface Renamed {
  username: string
  address: string
  sequence: number
  /** RFC 3339. */
  oldAddressReceivesUntil: string
  /** RFC 3339. */
  oldNameFreeAt: string
}

/** Why a rename or a drop was refused: the server's `code`, with `retryAt` for the limits. */
export class NameRefusedError extends Error {
  constructor(
    readonly code: string,
    readonly retryAt: string | null = null,
  ) {
    super(`refused: ${code}`)
    this.name = 'NameRefusedError'
  }
}

function refusal(error: unknown): NameRefusedError | null {
  if (!isAxiosError(error)) return null
  const body = error.response?.data as { code?: unknown; retryAt?: unknown } | undefined
  if (typeof body?.code !== 'string') return null
  return new NameRefusedError(body.code, typeof body.retryAt === 'string' ? body.retryAt : null)
}

interface RenameRequest {
  grant: string
  rename: AccountRenameV1
  mailAddress?: FirstAddressKey
}

/**
 * Renames the signed-in account to `name`. `needsKey` is what the check
 * answered: the new address's first key goes with the rename then (a name
 * taken back whose address kept its keys needs none). Throws
 * `WrongPasswordError` / `ReauthLockedError` for the password and
 * {@link NameRefusedError} for what the server refused.
 */
export async function renameAccount(name: string, needsKey: boolean, password: OneUseSecret): Promise<Renamed> {
  const session = getSession()
  if (!session) throw new Error('not signed in')
  // The password first: nothing is built for a wrong one.
  const grant = await accountGrant(password.take(), 'rename')
  const masterKey = toBase64(session.masterKey)
  // Where the chain ends and the address it ends at, read now. Another device
  // may have renamed since this page loaded: then this rename is no longer
  // the one the person chose, and they are told so.
  const { data: me } = await api.get<MeResponse>('/user/me')
  const [signedFrom, shown] = await Promise.all([foldAddress(me.address), foldAddress(session.address)])
  if (signedFrom === null || signedFrom !== shown) throw await changedElsewhere()
  const domain = me.address.slice(me.address.lastIndexOf('@') + 1)
  const address = `${name}@${domain}`
  // A name taken back keeps its address's keys: none is made over them,
  // whatever the check said. One's own freed name must continue its old
  // key list, which isn't built yet: refused, not restarted at 1 (every
  // device that saw the old list would take a restart for a rollback).
  const own = needsKey ? await ownAddressState(address) : 'keyed'
  if (own === 'freed') throw new NameRefusedError('ownFreedName')
  const body: RenameRequest = {
    grant,
    rename: await signAccountRename(masterKey, me.renames.sequence + 1, me.address, address, Date.now()),
    ...(own === 'none' ? { mailAddress: await firstAddressKey(session, address) } : {}),
  }
  try {
    return (await api.post<Renamed>('/user/rename', body)).data
  } catch (error) {
    const refused = refusal(error)
    if (refused?.code === 'renameConflict') throw await changedElsewhere()
    if (refused?.code === 'renameInvalid') {
      // Refused as no longer starting where the account is: renamed meanwhile.
      const { data: now } = await api.get<MeResponse>('/user/me')
      if (now.address !== me.address || now.renames.sequence !== me.renames.sequence) throw await changedElsewhere()
    }
    throw refused ?? error
  }
}

/** The account's name changed on another device: this page reads it again. */
async function changedElsewhere(): Promise<NameRefusedError> {
  await recheckAccount().catch(() => undefined)
  return new NameRefusedError('renameConflict')
}

export const namesKey = ['account-names'] as const

/** One of the account's names: the current one, or one it holds. */
export interface AccountName {
  name: string
  state: 'current' | 'held'
  /** RFC 3339; when a held name stops receiving (past: it no longer does). */
  receiveUntil: string | null
  /** RFC 3339; when a held name is freed for anyone. */
  freeAt: string | null
}

export function useAccountNames() {
  return useQuery({
    queryKey: namesKey,
    queryFn: async () => (await api.get<AccountName[]>('/user/names')).data,
  })
}

export interface RenameInput {
  name: string
  needsKey: boolean
  password: OneUseSecret
}

export function useRenameAccount() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ name, needsKey, password }: RenameInput) => renameAccount(name, needsKey, password),
    onSettled: async (renamed) => {
      // The new name in every view of this app (the other apps learn it from
      // the session version, docs/api.md).
      if (renamed) await recheckAccount().catch(() => undefined)
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: meKey }),
        queryClient.invalidateQueries({ queryKey: namesKey }),
        queryClient.invalidateQueries({ queryKey: securityEventsKey }),
      ])
    },
  })
}

/** Ends receiving at a held name now (`DELETE /api/user/names/:name`); it stays held until its date. */
export async function dropName(name: string, password: OneUseSecret): Promise<void> {
  const grant = await accountGrant(password.take(), 'rename')
  try {
    await api.delete(`/user/names/${encodeURIComponent(name)}`, { data: { grant } })
  } catch (error) {
    throw refusal(error) ?? error
  }
}

export function useDropName() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ name, password }: { name: string; password: OneUseSecret }) => dropName(name, password),
    onSettled: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: namesKey }),
        queryClient.invalidateQueries({ queryKey: securityEventsKey }),
      ])
    },
  })
}
