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

/** Too many wrong passwords: the account's sign-in lockout is on. */
export class ReauthLockedError extends Error {
  constructor() {
    super('too many failed attempts')
    this.name = 'ReauthLockedError'
  }
}

/**
 * The signed-in account's login key for `password` (base64), derived as
 * sign-in derives it, for the server to check: the re-check below, and
 * setting or removing Kutup Pass's PIN.
 */
export async function accountLoginKey(password: string): Promise<string> {
  const session = getSession()
  if (!session) throw new Error('not signed in')
  const { data } = await api.get<Preflight>('/auth/login/preflight', { params: { email: session.email } })
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
    if (isAxiosError(error) && error.response?.status === 429) throw new ReauthLockedError()
    throw error
  }
}
