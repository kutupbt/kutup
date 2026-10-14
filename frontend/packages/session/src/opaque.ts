// The OPAQUE exchanges with the server (docs/plans/opaque.md §6), shared by
// sign-in, reauthentication, sign-up, password change, recovery and the
// administrator's temporary passwords. The cryptography runs in a worker
// (@kutup/crypto/opaqueWorker); this file sequences it against the API.

import { startOpaqueRegistration, startOpaqueSignIn, type OpaqueSignIn } from '@kutup/crypto/opaqueWorker'
import api from './client'

/** What a grant authorizes (one use, a few minutes, bound to the account). */
export type GrantPurpose = 'pass' | 'passwordChange' | 'totp' | 'deleteAccount' | 'adminReset'

interface LoginStartResponse {
  loginId: string
  credentialResponse: string
  suite: number
}

/**
 * Runs `login/start` and `login/finish` for `name` and `password`: the
 * server's answer to the finish, and the sign-in (holding the export key,
 * to open the master key with; close it when done). A wrong password throws
 * `OpaqueAuthFailed` before anything is sent to finish.
 */
export async function opaqueLogin<T>(
  name: string,
  password: string,
  purpose: { purpose: 'session' } | { purpose: 'reauth'; for: GrantPurpose },
): Promise<{ data: T; signIn: OpaqueSignIn }> {
  const signIn = await startOpaqueSignIn(password)
  try {
    const { data: start } = await api.post<LoginStartResponse>('/auth/login/start', {
      name,
      credentialRequest: signIn.request,
      ...purpose,
    })
    const credentialFinalization = await signIn.finish(start.credentialResponse)
    const { data } = await api.post<T>('/auth/login/finish', { loginId: start.loginId, credentialFinalization })
    return { data, signIn }
  } catch (error) {
    signIn.close()
    throw error
  }
}

/** How a registration is allowed: a grant, or a bearer token (an administrator-made account's setup). */
export type RegistrationAuth = { grant: string } | { setupToken: string } | null

/** A registered password: what the server stores, and the master key's password envelope. */
export interface RegisteredPassword {
  opaqueRecord: string
  opaqueServerKeyId: number
  masterKeyEnvelope: string
}

/** A temporary password an administrator sets: no keys exist yet, so no envelope. */
export type RegisteredTemporaryPassword = Omit<RegisteredPassword, 'masterKeyEnvelope'>

/**
 * Registers `password` for the account bound to `keyBinding`, and seals its
 * `masterKey` under it: `register/start` (allowed by `auth`; none for a new
 * account), then the record and the envelope, which the caller sends with
 * the request that stores them.
 */
export async function opaqueRegister(
  password: string,
  keyBinding: string,
  masterKey: Uint8Array,
  auth: RegistrationAuth,
): Promise<RegisteredPassword>
export async function opaqueRegister(
  password: string,
  keyBinding: string,
  masterKey: null,
  auth: RegistrationAuth,
): Promise<RegisteredTemporaryPassword>
export async function opaqueRegister(
  password: string,
  keyBinding: string,
  masterKey: Uint8Array | null,
  auth: RegistrationAuth,
): Promise<RegisteredPassword | RegisteredTemporaryPassword> {
  const registration = await startOpaqueRegistration(password)
  try {
    const { data } = await api.post<{ registrationResponse: string; serverKeyId: number }>(
      '/auth/opaque/register/start',
      {
        keyBinding,
        registrationRequest: registration.request,
        ...(auth && 'grant' in auth ? { grant: auth.grant } : {}),
      },
      auth && 'setupToken' in auth ? { headers: { Authorization: `Bearer ${auth.setupToken}` } } : undefined,
    )
    const opaqueRecord = await registration.finish(data.registrationResponse)
    if (!masterKey) return { opaqueRecord, opaqueServerKeyId: data.serverKeyId }
    const masterKeyEnvelope = await registration.sealMasterKey(masterKey, keyBinding)
    return { opaqueRecord, opaqueServerKeyId: data.serverKeyId, masterKeyEnvelope }
  } finally {
    registration.close()
  }
}

/**
 * Replaces the account's password with `password` (a password change, a
 * recovery, a rotation to a new server setup), allowed by `grant`.
 */
export async function opaqueReregister(
  password: string,
  keyBinding: string,
  masterKey: Uint8Array,
  grant: string,
): Promise<void> {
  const registered = await opaqueRegister(password, keyBinding, masterKey, { grant })
  await api.post('/auth/opaque/register/finish', { grant, keyBinding, ...registered })
}
