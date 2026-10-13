// The account app's sign-in flows. The crypto steps are the canonical ones
// from @kutup/crypto (Argon2id in a worker, typed account envelopes); this
// file sequences them against the API and hands the unlocked keys to the
// session layer, which activates and persists them for this origin.

import {
  ACCOUNT_ENVELOPE_PURPOSE,
  ACCOUNT_PROTECTION_DEFAULTS,
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
import { signDriveKeyBinding } from '@kutup/crypto/identityPins'
import type { AccountProtectionConfig } from '@kutup/crypto/kdf'
import { loadServerSettings } from '@kutup/session/apps'
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
  /** What the account's keys are bound to (docs/plans/account-identity.md); only with a session. */
  envelopeBinding?: string
  requiresTotp?: boolean
  preAuthToken?: string
  requiresSetup?: boolean
  setupToken?: string
}

/** A second factor is due. Holds the derived key-encryption key, never the password. */
export interface TotpChallenge {
  name: string
  preAuthToken: string
  keyEncryptionKey: Uint8Array
}

/** An administrator-created account signing in for the first time. */
export interface PendingSetup {
  name: string
  /** The account's username, which its new Drive key binding names. */
  username: string
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
  binding: string,
  keyEncryptionKey: Uint8Array,
): Promise<void> {
  // The master envelope opens only under its own binding (suite 2 derives
  // the key from it), so once it has opened the binding is verified.
  const masterKey = await decryptMasterKey(response.masterKeyEnvelope, keyEncryptionKey, binding)
  const privateKey = await decryptPrivateKey(response.drivePrivateKeyEnvelope, masterKey, binding)
  await activate(response, {
    userId: response.userId,
    masterKey,
    privateKey,
    publicKey: response.publicKey,
    keyBinding: binding,
  })
}

async function activate(
  response: Pick<LoginResponse, 'accessToken' | 'sessionId'>,
  keys: SessionKeys,
): Promise<void> {
  await activateSession(keys, response.accessToken, response.sessionId)
  await persistKeys(response.sessionId, keys)
}

/** The address an account has on this server, which its binding names. */
async function accountAddress(username: string): Promise<string> {
  const settings = await loadServerSettings<{ chat?: { serverName?: string | null } }>()
  const server = settings.chat?.serverName
  if (!server) throw new Error('the server did not publish its name')
  return `${username}@${server}`
}

/**
 * The account's Drive key binding (docs/plans/drive-identity-pins.md): its
 * authority vouching for its Drive keys under its address, so the people it
 * shares with can check them. Sent with every new set of keys.
 */
async function driveKeyBindingFor(keys: AccountKeys, username: string): Promise<string> {
  return signDriveKeyBinding(toBase64(keys.masterKey), await accountAddress(username))
}

/**
 * Username (or Kutup address) + password, derived under the salt preflight
 * answers, for every account: one an administrator created too (its
 * temporary password was derived in the administrator's browser), which the
 * server answers with `requiresSetup`. The keys' binding comes only with the
 * session.
 */
export async function signIn(name: string, password: string): Promise<SignInResult> {
  const { data: preflight } = await api.get<Preflight>('/auth/login/preflight', {
    params: { name },
  })
  const derived = await deriveAccountProtectionInWorker(password, protectionFrom(preflight))
  const keyEncryptionKey = derived.keyEncryptionKey
  const loginKey = toBase64(derived.loginKey)

  const { data } = await api.post<LoginResponse>('/auth/login', { name, loginKey })
  if (data.requiresSetup && data.setupToken) {
    keyEncryptionKey.fill(0)
    return { kind: 'setup', setup: { name, username: data.username, setupToken: data.setupToken } }
  }
  if (data.requiresTotp && data.preAuthToken) {
    return { kind: 'totp', challenge: { name, preAuthToken: data.preAuthToken, keyEncryptionKey } }
  }
  return finishSignIn(data, keyEncryptionKey)
}

/** Unlocks and activates. */
async function finishSignIn(data: LoginResponse, keyEncryptionKey: Uint8Array): Promise<SignInResult> {
  const binding = data.envelopeBinding
  if (!binding) {
    keyEncryptionKey.fill(0)
    throw new Error('the server did not say what the keys are bound to')
  }
  try {
    await unlockAndActivate(data, binding, keyEncryptionKey)
  } finally {
    keyEncryptionKey.fill(0)
  }
  return { kind: 'signedIn' }
}

export async function completeTotp(challenge: TotpChallenge, code: string): Promise<SignInResult> {
  const { data } = await api.post<LoginResponse>('/auth/login/2fa', {
    preAuthToken: challenge.preAuthToken,
    code,
  })
  return finishSignIn(data, challenge.keyEncryptionKey)
}

/** Fresh account keys bound to a key binding drawn here (Argon2id in a worker). */
export interface AccountKeys extends RegistrationKeys {
  keyBinding: string
}

/** Fresh account keys: master key, recovery phrase, envelopes, all bound to a new key binding. */
export async function generateAccountKeys(password: string): Promise<AccountKeys> {
  const keyBinding = crypto.randomUUID()
  return { ...(await generateRegistrationInWorker(password, keyBinding)), keyBinding }
}

function registrationBody(keys: AccountKeys) {
  return {
    keyBinding: keys.keyBinding,
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

/** Key sets whose account the server has already created. */
const registered = new WeakSet<AccountKeys>()

/**
 * Create the account, then sign in with the login key already in memory — no
 * second Argon2id run and no retyped password. Safe to call again with the
 * same keys when the sign-in half failed (a rate limit, a lost connection):
 * the account is created once, and a retry only signs in.
 */
export async function registerAndSignIn(username: string, keys: AccountKeys, registrationCode?: string): Promise<void> {
  if (!registered.has(keys)) {
    const driveKeyBinding = await driveKeyBindingFor(keys, username)
    await api.post('/auth/register', {
      username,
      ...(registrationCode ? { registrationCode } : {}),
      ...registrationBody(keys),
      driveKeyBinding,
    })
    registered.add(keys)
  }
  const { data } = await api.post<LoginResponse>('/auth/login', { name: username, loginKey: keys.loginKey })
  await activate(data, {
    userId: data.userId,
    masterKey: keys.masterKey,
    privateKey: keys.privateKey,
    publicKey: keys.publicKey,
    keyBinding: keys.keyBinding,
  })
}

/** First sign-in of an administrator-created account: store its new keys. */
export async function completeSetup(setup: PendingSetup, keys: AccountKeys): Promise<void> {
  const driveKeyBinding = await driveKeyBindingFor(keys, setup.username)
  const { data } = await api.post<LoginResponse>(
    '/auth/complete-setup',
    { ...registrationBody(keys), driveKeyBinding },
    { headers: { Authorization: `Bearer ${setup.setupToken}` } },
  )
  await activate(data, {
    userId: data.userId,
    masterKey: keys.masterKey,
    privateKey: keys.privateKey,
    publicKey: keys.publicKey,
    keyBinding: keys.keyBinding,
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
  name: string,
  mnemonic: string,
  newPassword: string,
): Promise<void> {
  const { data } = await api.get<{ recoveryKeyEnvelope: string; envelopeBinding: string }>('/auth/recover/preflight', {
    params: { name },
  })
  const binding = data.envelopeBinding
  const { decodeMnemonic } = await import('@kutup/crypto/mnemonic')
  const recoveryKey = decodeMnemonic(normalizeMnemonic(mnemonic))
  const masterKey = await openAccountEnvelope(
    data.recoveryKeyEnvelope,
    recoveryKey,
    ACCOUNT_ENVELOPE_PURPOSE.recoveryMasterKey,
    binding,
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
      binding,
    )
    const recoveryProof = await deriveRecoveryAuthProof(toBase64(recoveryKey), binding)
    await api.post('/auth/recover', {
      name,
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

