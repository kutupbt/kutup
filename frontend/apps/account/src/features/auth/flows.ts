// The account app's sign-in flows. The crypto steps are the canonical ones
// from @kutup/crypto (Argon2id in a worker, typed account envelopes); this
// file sequences them against the API and hands the unlocked keys to the
// session layer, which activates and persists them for this origin.

import {
  ACCOUNT_ENVELOPE_PURPOSE,
  ACCOUNT_PROTECTION_DEFAULTS,
  decodeMnemonic,
  decryptMasterKey,
  decryptPrivateKey,
  deriveRecoveryAuthProof,
  generateAccountProtectionSalt,
  openAccountEnvelope,
  sealAccountEnvelope,
  toBase64,
  type RegistrationKeys,
} from '@kutup/crypto'
import {
  deriveAccountProtectionInWorker,
  generateRegistrationInWorker,
} from '@kutup/crypto/accountProtectionWorker'
import type { AccountProtectionConfig } from '@kutup/crypto/kdf'
import api from '@kutup/session/client'
import type { SessionKeys } from '@kutup/session/keys'
import { persistKeys } from '@kutup/session/persist'
import { activateSession } from '@kutup/session/profile'

interface Preflight {
  accountProtectionSuite: number
  accountProtectionSalt: string
  argonMemoryKib: number
  argonIterations: number
  argonParallelism: number
}

interface LoginResponse {
  accessToken: string
  sessionId: string
  userId: string
  username: string
  masterKeyEnvelope: string
  drivePrivateKeyEnvelope: string
  publicKey: string
  requiresTotp?: boolean
  preAuthToken?: string
  requiresSetup?: boolean
  setupToken?: string
}

/** A second factor is due. Holds the derived key-encryption key, never the password. */
export interface TotpChallenge {
  email: string
  preAuthToken: string
  keyEncryptionKey: Uint8Array
}

/** An administrator-created account signing in for the first time. */
export interface PendingSetup {
  email: string
  setupToken: string
}

export type SignInResult =
  | { kind: 'signedIn' }
  | { kind: 'totp'; challenge: TotpChallenge }
  | { kind: 'setup'; setup: PendingSetup }

function protectionFrom(preflight: Preflight): AccountProtectionConfig {
  return {
    suite: preflight.accountProtectionSuite,
    salt: preflight.accountProtectionSalt,
    memoryKib: preflight.argonMemoryKib,
    iterations: preflight.argonIterations,
    parallelism: preflight.argonParallelism,
  }
}

async function unlockAndActivate(
  response: LoginResponse,
  email: string,
  keyEncryptionKey: Uint8Array,
): Promise<void> {
  const masterKey = await decryptMasterKey(response.masterKeyEnvelope, keyEncryptionKey, email)
  const privateKey = await decryptPrivateKey(response.drivePrivateKeyEnvelope, masterKey, email)
  await activate(response, { userId: response.userId, masterKey, privateKey, publicKey: response.publicKey })
}

async function activate(
  response: Pick<LoginResponse, 'accessToken' | 'sessionId'>,
  keys: SessionKeys,
): Promise<void> {
  await activateSession(keys, response.accessToken, response.sessionId)
  await persistKeys(response.sessionId, keys)
}

/**
 * Email + password. An account an administrator created still has no key
 * material (empty protection salt): its temporary password is sent as-is and
 * the server answers `requiresSetup`.
 */
export async function signIn(email: string, password: string): Promise<SignInResult> {
  const { data: preflight } = await api.get<Preflight>('/auth/login/preflight', {
    params: { email },
  })
  const protection = protectionFrom(preflight)
  let loginKey: string
  let keyEncryptionKey: Uint8Array | null = null
  if (protection.salt === '') {
    loginKey = toBase64(new TextEncoder().encode(password))
  } else {
    const derived = await deriveAccountProtectionInWorker(password, protection)
    keyEncryptionKey = derived.keyEncryptionKey
    loginKey = toBase64(derived.loginKey)
  }

  const { data } = await api.post<LoginResponse>('/auth/login', { email, loginKey })
  if (data.requiresSetup && data.setupToken) {
    return { kind: 'setup', setup: { email, setupToken: data.setupToken } }
  }
  if (!keyEncryptionKey) throw new Error('the server returned a session for an account without keys')
  if (data.requiresTotp && data.preAuthToken) {
    return { kind: 'totp', challenge: { email, preAuthToken: data.preAuthToken, keyEncryptionKey } }
  }
  try {
    await unlockAndActivate(data, email, keyEncryptionKey)
  } finally {
    keyEncryptionKey.fill(0)
  }
  return { kind: 'signedIn' }
}

export async function completeTotp(challenge: TotpChallenge, code: string): Promise<void> {
  const { data } = await api.post<LoginResponse>('/auth/login/2fa', {
    preAuthToken: challenge.preAuthToken,
    code,
  })
  await unlockAndActivate(data, challenge.email, challenge.keyEncryptionKey)
  challenge.keyEncryptionKey.fill(0)
}

/** Fresh account keys: master key, recovery phrase, envelopes (Argon2id in a worker). */
export function generateAccountKeys(password: string, email: string): Promise<RegistrationKeys> {
  return generateRegistrationInWorker(password, email)
}

function registrationBody(keys: RegistrationKeys) {
  return {
    loginKey: keys.loginKey,
    masterKeyEnvelope: keys.masterKeyEnvelope,
    recoveryKeyEnvelope: keys.recoveryKeyEnvelope,
    drivePrivateKeyEnvelope: keys.drivePrivateKeyEnvelope,
    publicKey: keys.publicKey,
    accountAuthorityPublicKey: keys.accountAuthorityPublicKey,
    accountAuthorityKeyId: keys.accountAuthorityKeyId,
    accountIncarnationId: keys.accountIncarnationId,
    driveSigningPublicKey: keys.driveSigningPublicKey,
    accountProtectionSuite: keys.accountProtectionSuite,
    accountProtectionSalt: keys.accountProtectionSalt,
    argonMemoryKib: keys.argonMemoryKib,
    argonIterations: keys.argonIterations,
    argonParallelism: keys.argonParallelism,
    recoveryProof: keys.recoveryProof,
  }
}

/**
 * Create the account, then sign in with the login key already in memory — no
 * second Argon2id run and no retyped password.
 */
export async function registerAndSignIn(
  email: string,
  username: string,
  keys: RegistrationKeys,
): Promise<void> {
  await api.post('/auth/register', { email, username, ...registrationBody(keys) })
  const { data } = await api.post<LoginResponse>('/auth/login', { email, loginKey: keys.loginKey })
  await activate(data, {
    userId: data.userId,
    masterKey: keys.masterKey,
    privateKey: keys.privateKey,
    publicKey: keys.publicKey,
  })
}

/** First sign-in of an administrator-created account: store its new keys. */
export async function completeSetup(setup: PendingSetup, keys: RegistrationKeys): Promise<void> {
  const { data } = await api.post<LoginResponse>(
    '/auth/complete-setup',
    { email: setup.email, ...registrationBody(keys) },
    { headers: { Authorization: `Bearer ${setup.setupToken}` } },
  )
  await activate(data, {
    userId: data.userId,
    masterKey: keys.masterKey,
    privateKey: keys.privateKey,
    publicKey: keys.publicKey,
  })
}

/** Normalise a typed recovery phrase: numbering, case and spacing do not matter. */
export function normalizeMnemonic(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/\b\d+[.)]\s*/g, '')
    .replace(/\s+/g, ' ')
    .trim()
}

/**
 * Reset the password with the 24-word recovery phrase. The phrase unwraps the
 * master key locally; the server only receives a proof derived from it and a
 * new password wrapping. Every existing session of the account ends.
 * (The phrase is the second factor, so 2FA is not asked.)
 */
export async function recoverAccount(
  email: string,
  mnemonic: string,
  newPassword: string,
): Promise<void> {
  const { data } = await api.get<{ recoveryKeyEnvelope: string }>('/auth/recover/preflight', {
    params: { email },
  })
  const recoveryKey = decodeMnemonic(normalizeMnemonic(mnemonic))
  const masterKey = await openAccountEnvelope(
    data.recoveryKeyEnvelope,
    recoveryKey,
    ACCOUNT_ENVELOPE_PURPOSE.recoveryMasterKey,
    email,
  )
  const protection = {
    ...ACCOUNT_PROTECTION_DEFAULTS,
    salt: toBase64(generateAccountProtectionSalt()),
  }
  const { keyEncryptionKey, loginKey } = await deriveAccountProtectionInWorker(newPassword, protection)
  try {
    const newMasterKeyEnvelope = await sealAccountEnvelope(
      masterKey,
      keyEncryptionKey,
      ACCOUNT_ENVELOPE_PURPOSE.passwordMasterKey,
      email,
    )
    const recoveryProof = await deriveRecoveryAuthProof(toBase64(recoveryKey), email)
    await api.post('/auth/recover', {
      email,
      newLoginKey: toBase64(loginKey),
      newMasterKeyEnvelope,
      newAccountProtectionSuite: protection.suite,
      newAccountProtectionSalt: protection.salt,
      newArgonMemoryKib: protection.memoryKib,
      newArgonIterations: protection.iterations,
      newArgonParallelism: protection.parallelism,
      recoveryProof,
    })
  } finally {
    masterKey.fill(0)
    recoveryKey.fill(0)
    keyEncryptionKey.fill(0)
    loginKey.fill(0)
  }
}
