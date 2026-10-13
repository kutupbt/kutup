// Checking the account password in a signed-in app (Kutup Pass's lock,
// docs/plans/pass.md), the way sign-in checks it: the login key derived from
// the typed password (Argon2id in a worker, with the account's public
// preflight parameters) is verified by the server against its hash, under
// the sign-in lockout and rate limit. Nothing secret comes back.

import { isAxiosError } from 'axios'
import { toBase64 } from '@kutup/crypto/base64'
import { deriveAccountProtectionInWorker } from '@kutup/crypto/accountProtectionWorker'
import api from './client'
import { getSession } from './store'

interface Preflight {
  accountProtectionSuite: number
  accountProtectionSalt: string
  argonMemoryKib: number
  argonIterations: number
  argonParallelism: number
}

/**
 * The server holds the check back: `accountLocked` after too many wrong
 * passwords for the account (as at sign-in, for a while), `rateLimited`
 * when this address asked too often (a minute).
 */
export class ReauthLockedError extends Error {
  constructor(readonly reason: 'accountLocked' | 'rateLimited' = 'accountLocked') {
    super('too many failed attempts')
    this.name = 'ReauthLockedError'
  }
}

/** The {@link ReauthLockedError} a 429 stands for, or null for anything else. */
export function lockedErrorFrom(error: unknown): ReauthLockedError | null {
  if (!isAxiosError(error) || error.response?.status !== 429) return null
  const code = (error.response.data as { code?: string } | undefined)?.code
  return new ReauthLockedError(code === 'rateLimited' ? 'rateLimited' : 'accountLocked')
}

/**
 * The signed-in account's login key for `password` (base64), derived as
 * sign-in derives it, for the server to check: the re-check below, and
 * setting or removing Kutup Pass's PIN.
 */
export async function accountLoginKey(password: string): Promise<string> {
  const session = getSession()
  if (!session) throw new Error('not signed in')
  const { data } = await api.get<Preflight>('/auth/login/preflight', { params: { name: session.username ?? session.address } })
  const { keyEncryptionKey, loginKey } = await deriveAccountProtectionInWorker(password, {
    suite: data.accountProtectionSuite,
    salt: data.accountProtectionSalt,
    memoryKib: data.argonMemoryKib,
    iterations: data.argonIterations,
    parallelism: data.argonParallelism,
  })
  keyEncryptionKey.fill(0)
  try {
    return toBase64(loginKey)
  } finally {
    loginKey.fill(0)
  }
}

/**
 * Whether `password` is the signed-in account's password. Throws
 * {@link ReauthLockedError} during the lockout, and when Kutup cannot be
 * reached.
 */
export async function verifyAccountPassword(password: string): Promise<boolean> {
  if (!getSession() || !password) return false
  const loginKey = await accountLoginKey(password)
  try {
    await api.post('/user/reauth', { loginKey })
    return true
  } catch (error) {
    if (isAxiosError(error) && error.response?.status === 401) return false
    throw lockedErrorFrom(error) ?? error
  }
}
