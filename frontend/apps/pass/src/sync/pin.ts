// The PIN lock (docs/plans/pass.md, "The PIN"), as Proton Pass's: six digits
// per account, used on every device whose lock mode is the PIN. Like the
// password lock it releases no key (this tab still holds the vault's kept
// key); the server keeps and checks it so it cannot be worked through: three
// wrong PINs in a row end the sign-in. Setting or removing it takes the
// account password.

import { useQuery, useQueryClient } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import api from '@kutup/session/client'
import { accountLoginKey, lockedErrorFrom } from '@kutup/session/reauth'

export const PIN_LENGTH = 6

export function isPin(value: string): boolean {
  return value.length === PIN_LENGTH && /^\d+$/.test(value)
}

const PIN_KEY = ['pass', 'pin'] as const

/** Whether the account has a PIN. */
export function usePinStatus() {
  return useQuery({
    queryKey: PIN_KEY,
    queryFn: async () => (await api.get<{ set: boolean }>('/pass/pin')).data.set,
    staleTime: 60_000,
  })
}

export function useRefreshPinStatus(): () => Promise<void> {
  const client = useQueryClient()
  return () => client.invalidateQueries({ queryKey: PIN_KEY })
}

/** Why setting or removing the PIN was refused. */
export type PinChangeResult = 'ok' | 'wrongPassword' | 'paused'

async function withPassword(password: string, send: (loginKey: string) => Promise<unknown>): Promise<PinChangeResult> {
  const loginKey = await accountLoginKey(password)
  try {
    await send(loginKey)
    return 'ok'
  } catch (error) {
    if (isAxiosError(error) && error.response?.status === 401) return 'wrongPassword'
    if (isAxiosError(error) && error.response?.status === 429) return 'paused'
    throw error
  }
}

/** Sets or changes the account's PIN. */
export function setPin(password: string, pin: string): Promise<PinChangeResult> {
  return withPassword(password, (loginKey) => api.put('/pass/pin', { loginKey, pin }))
}

/** Removes the account's PIN. */
export function removePin(password: string): Promise<PinChangeResult> {
  return withPassword(password, (loginKey) => api.delete('/pass/pin', { data: { loginKey } }))
}

export type PinCheck =
  | { result: 'ok' }
  | { result: 'wrong'; attemptsLeft: number }
  /** The last try: the server ended the sign-in. */
  | { result: 'signedOut' }
  /** No PIN (removed, perhaps on another device). */
  | { result: 'noPin' }

/** Checks the PIN with the server. Throws when Kutup cannot be reached. */
export async function verifyPin(pin: string): Promise<PinCheck> {
  try {
    await api.post('/pass/pin/verify', { pin })
    return { result: 'ok' }
  } catch (error) {
    if (!isAxiosError(error)) throw error
    const body = error.response?.data as { code?: string; attemptsLeft?: number } | undefined
    if (error.response?.status === 404 && body?.code === 'noPin') return { result: 'noPin' }
    if (error.response?.status === 403 && body?.code === 'signedOut') return { result: 'signedOut' }
    if (error.response?.status === 403 && body?.code === 'wrongPin') return { result: 'wrong', attemptsLeft: body.attemptsLeft ?? 0 }
    throw lockedErrorFrom(error) ?? error
  }
}
