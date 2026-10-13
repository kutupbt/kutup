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
  resealAccountEnvelope,
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
import { rebindPassVaultSecrets } from '@kutup/session/passRebind'
import { persistKeys } from '@kutup/session/persist'
import { activateSession } from '@kutup/session/profile'
import { getSession, updateSession } from '@kutup/session/store'

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
  loginKey: string
}

/** An administrator-created account signing in for the first time. */
export interface PendingSetup {
  name: string
  setupToken: string
}

/**
 * An account whose keys are still bound to its old sign-in email: the account
 * app re-seals them to a key binding right after the sign-in
 * (docs/plans/account-identity.md). Holds the password's key-encryption key
 * and login key, never the password, until it is done or put off.
 */
export interface PendingRebind {
  name: string
  oldBinding: string
  keyEncryptionKey: Uint8Array
  loginKey: string
}

export type SignInResult =
  | { kind: 'signedIn'; rebind?: PendingRebind }
  | { kind: 'totp'; challenge: TotpChallenge }
  | { kind: 'setup'; setup: PendingSetup }

/** A key binding: what an account's keys are bound to for good (a UUID v4), never a name. */
export function isKeyBinding(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value)
}

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
  const masterKey = await decryptMasterKey(response.masterKeyEnvelope, keyEncryptionKey, binding)
  const privateKey = await decryptPrivateKey(response.drivePrivateKeyEnvelope, masterKey, binding)
  await activate(response, { userId: response.userId, masterKey, privateKey, publicKey: response.publicKey })
}

async function activate(
  response: Pick<LoginResponse, 'accessToken' | 'sessionId'>,
  keys: SessionKeys,
): Promise<void> {
  await activateSession(keys, response.accessToken, response.sessionId)
  await persistKeys(response.sessionId, keys)
  // In the background: signing in must not wait for it, and the next
  // sign-in tries again.
  void ensureDriveKeyBinding(keys.masterKey).catch(() => undefined)
}

/** The address an account has on this server, which its binding names. */
async function accountAddress(username: string): Promise<string> {
  const settings = await loadServerSettings<{ chat?: { serverName?: string | null } }>()
  const server = settings.chat?.serverName
  if (!server) throw new Error('the server did not publish its name')
  return `${username}@${server}`
}

/**
 * An account made before Drive key bindings (docs/plans/drive-identity-pins.md)
 * signs its own: its authority vouching for its Drive keys, so the people it
 * shares with can check them.
 */
async function ensureDriveKeyBinding(masterKey: Uint8Array): Promise<void> {
  const { data: me } = await api.get<{ username: string; hasDriveKeyBinding?: boolean }>('/user/me')
  if (me.hasDriveKeyBinding !== false || !me.username) return
  const driveKeyBinding = await signDriveKeyBinding(toBase64(masterKey), await accountAddress(me.username))
  await api.put('/user/drive-key-binding', { driveKeyBinding })
}

/**
 * Username (or Kutup address) + password, derived under the salt preflight
 * answers, for every account: one an administrator created too (its
 * temporary password was derived in the administrator's browser), which the
 * server answers with `requiresSetup`. The keys' binding comes only with the
 * session. An account whose keys are still bound to its old sign-in email
 * comes back with a pending re-seal.
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
    return { kind: 'setup', setup: { name, setupToken: data.setupToken } }
  }
  if (data.requiresTotp && data.preAuthToken) {
    return { kind: 'totp', challenge: { name, preAuthToken: data.preAuthToken, keyEncryptionKey, loginKey } }
  }
  return finishSignIn(data, name, keyEncryptionKey, loginKey)
}

/** Unlocks and activates; keeps the password keys for a re-seal when one is due. */
async function finishSignIn(data: LoginResponse, name: string, keyEncryptionKey: Uint8Array, loginKey: string): Promise<SignInResult> {
  const binding = data.envelopeBinding
  if (!binding) {
    keyEncryptionKey.fill(0)
    throw new Error('the server did not say what the keys are bound to')
  }
  try {
    await unlockAndActivate(data, binding, keyEncryptionKey)
  } catch (error) {
    keyEncryptionKey.fill(0)
    throw error
  }
  if (isKeyBinding(binding)) {
    keyEncryptionKey.fill(0)
    return { kind: 'signedIn' }
  }
  return { kind: 'signedIn', rebind: { name, oldBinding: binding, keyEncryptionKey, loginKey } }
}

export async function completeTotp(challenge: TotpChallenge, code: string): Promise<SignInResult> {
  const { data } = await api.post<LoginResponse>('/auth/login/2fa', {
    preAuthToken: challenge.preAuthToken,
    code,
  })
  return finishSignIn(data, challenge.name, challenge.keyEncryptionKey, challenge.loginKey)
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
export async function registerAndSignIn(username: string, keys: AccountKeys): Promise<void> {
  if (!registered.has(keys)) {
    const driveKeyBinding = await signDriveKeyBinding(toBase64(keys.masterKey), await accountAddress(username))
    await api.post('/auth/register', { username, ...registrationBody(keys), driveKeyBinding })
    registered.add(keys)
  }
  const { data } = await api.post<LoginResponse>('/auth/login', { name: username, loginKey: keys.loginKey })
  await activate(data, {
    userId: data.userId,
    masterKey: keys.masterKey,
    privateKey: keys.privateKey,
    publicKey: keys.publicKey,
  })
}

/** First sign-in of an administrator-created account: store its new keys. */
export async function completeSetup(setup: PendingSetup, keys: AccountKeys): Promise<void> {
  const { data } = await api.post<LoginResponse>(
    '/auth/complete-setup',
    registrationBody(keys),
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

/**
 * How the recovery part of a re-seal is made: with the phrase the reader has
 * (checked against the account), or a new one they were shown and confirmed
 * first (it replaces the old phrase).
 */
export type RecoveryChoice = { kind: 'phrase'; mnemonic: string } | { kind: 'new'; mnemonic: string }

/** A new recovery phrase, to show and confirm before a re-seal uses it. */
export async function newRecoveryPhrase(): Promise<string> {
  const { encodeMnemonic } = await import('@kutup/crypto/mnemonic')
  const entropy = crypto.getRandomValues(new Uint8Array(32))
  try {
    return encodeMnemonic(entropy)
  } finally {
    entropy.fill(0)
  }
}

/** The phrase was not this account's. */
export class WrongRecoveryPhrase extends Error {}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i])
}

/**
 * Moves every key of the account from its old sign-in email to a new key
 * binding (docs/plans/account-identity.md), in one request the server takes
 * only whole: the password and recovery wrappings of the master key (the
 * recovery one from the phrase the reader typed, or from a new one, returned
 * to be written down), the recovery check, the Drive key, the Chat backup
 * root, each mail address key and each Pass vault secret.
 */
export async function rebindAccount(pending: PendingRebind, choice: RecoveryChoice): Promise<void> {
  const session = getSession()
  if (!session) throw new Error('not signed in')
  const { masterKey, privateKey } = session
  const from = pending.oldBinding
  const keyBinding = crypto.randomUUID()
  const { decodeMnemonic } = await import('@kutup/crypto/mnemonic')
  let recoveryKey: Uint8Array
  try {
    recoveryKey = decodeMnemonic(normalizeMnemonic(choice.mnemonic))
  } catch {
    throw new WrongRecoveryPhrase('not a recovery phrase')
  }
  if (choice.kind === 'phrase') {
    // The phrase must open the account's recovery wrapping as it is now.
    const { data } = await api.get<{ recoveryKeyEnvelope: string }>('/auth/recover/preflight', { params: { name: pending.name } })
    const opened = await openAccountEnvelope(data.recoveryKeyEnvelope, recoveryKey, ACCOUNT_ENVELOPE_PURPOSE.recoveryMasterKey, from).catch(
      () => null,
    )
    const matches = !!opened && sameBytes(opened, masterKey)
    opened?.fill(0)
    if (!matches) {
      recoveryKey.fill(0)
      throw new WrongRecoveryPhrase('this phrase is not this account\'s')
    }
  }
  try {
    const seal = (plain: Uint8Array, key: Uint8Array, purpose: (typeof ACCOUNT_ENVELOPE_PURPOSE)[keyof typeof ACCOUNT_ENVELOPE_PURPOSE]) =>
      sealAccountEnvelope(plain, key, purpose, keyBinding)
    const backup = await api
      .get<{ provisioned?: boolean; rootEnvelope?: string | null }>('/chat/backup')
      .then((r) => r.data)
      .catch(() => null)
    const { data: addresses } = await api.get<{ keys: { id: string; privateKeyEnvelope: string }[] }[]>('/mail/addresses')
    const body = {
      loginKey: pending.loginKey,
      keyBinding,
      masterKeyEnvelope: await seal(masterKey, pending.keyEncryptionKey, ACCOUNT_ENVELOPE_PURPOSE.passwordMasterKey),
      recoveryKeyEnvelope: await seal(masterKey, recoveryKey, ACCOUNT_ENVELOPE_PURPOSE.recoveryMasterKey),
      recoveryProof: await deriveRecoveryAuthProof(toBase64(recoveryKey), keyBinding),
      drivePrivateKeyEnvelope: await seal(privateKey, masterKey, ACCOUNT_ENVELOPE_PURPOSE.driveHpkePrivateKey),
      chatBackupRootEnvelope:
        backup?.provisioned && backup.rootEnvelope
          ? await resealAccountEnvelope(backup.rootEnvelope, masterKey, ACCOUNT_ENVELOPE_PURPOSE.chatBackupRoot, from, keyBinding)
          : null,
      mailKeys: await Promise.all(
        addresses.flatMap((address) =>
          address.keys.map(async (key) => ({
            id: key.id,
            privateKeyEnvelope: await resealAccountEnvelope(key.privateKeyEnvelope, masterKey, ACCOUNT_ENVELOPE_PURPOSE.mailAddressPrivateKey, from, keyBinding),
          })),
        ),
      ),
      passVaultSecrets: await rebindPassVaultSecrets(masterKey, from, keyBinding),
    }
    await api.post('/user/rebind', body)
    updateSession({ envelopeBinding: keyBinding })
  } finally {
    recoveryKey.fill(0)
    pending.keyEncryptionKey.fill(0)
  }
}

/** Puts the re-seal off: the keys it held are dropped; it comes back at the next sign-in. */
export function dropPendingRebind(pending: PendingRebind): void {
  pending.keyEncryptionKey.fill(0)
}
