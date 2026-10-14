// Checking the account password in a signed-in app (Kutup Pass's lock,
// docs/plans/pass.md; a password change; an administrator's reset), the way
// sign-in checks it: OPAQUE (docs/plans/opaque.md), under the sign-in lockout
// and rate limit. A right password earns a grant: one use, a few minutes,
// bound to this session and to what it was asked for. The password never
// leaves the browser.

import { isAxiosError } from 'axios'
import { OpaqueAuthFailed } from '@kutup/crypto/opaqueWorker'
import { opaqueLogin, type GrantPurpose } from './opaque'
import { getSession } from './store'

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

function bodyCode(error: unknown): string | undefined {
  return isAxiosError(error) ? (error.response?.data as { code?: string } | undefined)?.code : undefined
}

/** The {@link ReauthLockedError} a 429 stands for, or null for anything else. */
export function lockedErrorFrom(error: unknown): ReauthLockedError | null {
  if (!isAxiosError(error) || error.response?.status !== 429) return null
  return new ReauthLockedError(bodyCode(error) === 'rateLimited' ? 'rateLimited' : 'accountLocked')
}

/** The password is not the account's. */
export class WrongPasswordError extends Error {
  constructor() {
    super('the password is not right')
    this.name = 'WrongPasswordError'
  }
}

/**
 * A password handed to a mutation that is read once, then gone: react-query
 * keeps a mutation's variables (`mutation.variables`) until it is reset.
 */
export class OneUseSecret {
  #value: string | null

  constructor(value: string) {
    this.#value = value
  }

  take(): string {
    const value = this.#value
    this.#value = null
    if (value === null) throw new Error('the password was already used')
    return value
  }
}

/**
 * A grant for `purpose`, for the signed-in account's `password`. Throws
 * {@link WrongPasswordError} for a wrong password, {@link ReauthLockedError}
 * during the lockout, and the request's error when Kutup cannot be reached.
 */
export async function accountGrant(password: string, purpose: GrantPurpose): Promise<string> {
  const session = getSession()
  if (!session) throw new Error('not signed in')
  try {
    const { data, signIn } = await opaqueLogin<{ grant: string }>(session.username ?? session.address, password, {
      purpose: 'reauth',
      for: purpose,
    })
    signIn.close()
    return data.grant
  } catch (error) {
    if (error instanceof OpaqueAuthFailed) throw new WrongPasswordError()
    // Only a refused password is a wrong one; any other 401 is the sign-in
    // ending (the client has sent it to sign in again), thrown as it is.
    if (isAxiosError(error) && error.response?.status === 401 && bodyCode(error) === 'invalidCredentials') {
      throw new WrongPasswordError()
    }
    throw lockedErrorFrom(error) ?? error
  }
}

/**
 * Whether `password` is the signed-in account's password. Throws
 * {@link ReauthLockedError} during the lockout, and when Kutup cannot be
 * reached.
 */
export async function verifyAccountPassword(password: string): Promise<boolean> {
  if (!getSession() || !password) return false
  try {
    await accountGrant(password, 'pass')
    return true
  } catch (error) {
    if (error instanceof WrongPasswordError) return false
    throw error
  }
}
