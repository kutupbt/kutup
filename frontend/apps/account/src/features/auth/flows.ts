// The account app's sign-in flows. The crypto steps are the canonical ones
// from @kutup/crypto (Argon2id in a worker, typed account envelopes); this
// file sequences them against the API and hands the unlocked keys to the
// session layer, which activates and persists them for this origin.

import {
  ACCOUNT_ENVELOPE_PURPOSE,
  decryptPrivateKey,
  generateAccountKeySet,
  openAccountEnvelope,
  toBase64,
  deriveRecoveryAuthProof,
  type AccountKeySet,
} from '@kutup/crypto'
import type { OpaqueSignIn } from '@kutup/crypto/opaqueWorker'
import { signDriveKeyBinding } from '@kutup/crypto/identityPins'
import { loadServerSettings } from '@kutup/session/apps'
import api from '@kutup/session/client'
import type { SessionKeys } from '@kutup/session/keys'
import { opaqueLogin, opaqueRegister, opaqueReregister, type RegistrationAuth } from '@kutup/session/opaque'
import { persistKeys } from '@kutup/session/persist'
import { activateSession } from '@kutup/session/profile'

interface LoginResponse {
  accessToken: string
  sessionId: string
  userId: string
  username: string
  masterKeyEnvelope: string
  drivePrivateKeyEnvelope: string
  publicKey: string
  /** What the account's keys are bound to (docs/plans/account-identity.md); only with a session. */
  keyBinding?: string
  requiresTotp?: boolean
  preAuthToken?: string
  requiresSetup?: boolean
  setupToken?: string
  /** The server moved to a new OPAQUE setup: re-register with this grant (purpose `rotate`). */
  rotate?: boolean
  grant?: string
}

/** A second factor is due. Holds the open sign-in (its export key, in its worker), never the password. */
export interface TotpChallenge {
  name: string
  preAuthToken: string
  signIn: OpaqueSignIn
  /** Re-registers the password when the server asks (a rotation); captured, not stored. */
  rotate: (keyBinding: string, masterKey: Uint8Array, grant: string) => Promise<void>
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
 * Username (or Kutup address) + password, through OPAQUE: the password never
 * leaves this browser, and the master key's envelope comes only after the
 * server accepted the proof. An administrator-created account answers
 * `requiresSetup`; one with a second factor, `requiresTotp`.
 */
export async function signIn(name: string, password: string): Promise<SignInResult> {
  const { data, signIn: opened } = await opaqueLogin<LoginResponse>(name, password, { purpose: 'session' })
  if (data.requiresSetup && data.setupToken) {
    opened.close()
    return { kind: 'setup', setup: { name, username: data.username, setupToken: data.setupToken } }
  }
  const rotate = (keyBinding: string, masterKey: Uint8Array, grant: string) =>
    opaqueReregister(password, keyBinding, masterKey, grant)
  if (data.requiresTotp && data.preAuthToken) {
    return { kind: 'totp', challenge: { name, preAuthToken: data.preAuthToken, signIn: opened, rotate } }
  }
  return finishSignIn(data, opened, rotate)
}

/** Opens the master key with the sign-in's export key, activates, and re-registers if the server asks. */
async function finishSignIn(data: LoginResponse, opened: OpaqueSignIn, rotate: TotpChallenge['rotate']): Promise<SignInResult> {
  try {
    const binding = data.keyBinding
    if (!binding) throw new Error('the server did not say what the keys are bound to')
    // The master envelope opens only under its own binding, so once it has
    // opened the binding is verified.
    const masterKey = await opened.openMasterKey(data.masterKeyEnvelope, binding)
    const privateKey = await decryptPrivateKey(data.drivePrivateKeyEnvelope, masterKey, binding)
    await activate(data, { userId: data.userId, masterKey, privateKey, publicKey: data.publicKey, keyBinding: binding })
    // A new server setup: the password just used is registered again under it,
    // without asking. A failure leaves the old record, and the next sign-in
    // asks again.
    if (data.rotate && data.grant) await rotate(binding, masterKey, data.grant).catch(() => undefined)
  } finally {
    opened.close()
  }
  return { kind: 'signedIn' }
}

export async function completeTotp(challenge: TotpChallenge, code: string): Promise<SignInResult> {
  const { data } = await api.post<LoginResponse>('/auth/login/2fa', {
    preAuthToken: challenge.preAuthToken,
    code,
  })
  return finishSignIn(data, challenge.signIn, challenge.rotate)
}

/** Ends a sign-in waiting for its second factor (the user went back). */
export function abandonTotp(challenge: TotpChallenge): void {
  challenge.signIn.close()
}

/** Fresh account keys bound to a key binding drawn here, with the password registered. */
export interface AccountKeys extends AccountKeySet {
  keyBinding: string
  opaqueRecord: string
  opaqueServerKeyId: number
  masterKeyEnvelope: string
}

/**
 * Fresh account keys (master key, recovery phrase, envelopes, all bound to a
 * new key binding) and the password registered for them (OPAQUE; Argon2id in
 * a worker). `setupToken`: an administrator-created account's first sign-in.
 */
export async function generateAccountKeys(password: string, setupToken?: string): Promise<AccountKeys> {
  const keyBinding = crypto.randomUUID()
  const keys = await generateAccountKeySet(keyBinding)
  const auth: RegistrationAuth = setupToken ? { setupToken } : null
  const registered = await opaqueRegister(password, keyBinding, keys.masterKey, auth)
  return { ...keys, keyBinding, ...registered }
}

function registrationBody(keys: AccountKeys) {
  return {
    keyBinding: keys.keyBinding,
    opaqueRecord: keys.opaqueRecord,
    opaqueServerKeyId: keys.opaqueServerKeyId,
    masterKeyEnvelope: keys.masterKeyEnvelope,
    recoveryKeyEnvelope: keys.recoveryKeyEnvelope,
    drivePrivateKeyEnvelope: keys.drivePrivateKeyEnvelope,
    publicKey: keys.publicKey,
    accountAuthorityPublicKey: keys.accountAuthorityPublicKey,
    accountAuthorityKeyId: keys.accountAuthorityKeyId,
    accountIncarnationId: keys.accountIncarnationId,
    driveSigningPublicKey: keys.driveSigningPublicKey,
    recoveryProof: keys.recoveryProof,
  }
}

function sessionKeys(keys: AccountKeys): SessionKeys {
  return {
    userId: '',
    masterKey: keys.masterKey,
    privateKey: keys.privateKey,
    publicKey: keys.publicKey,
    keyBinding: keys.keyBinding,
  }
}

/** Sessions the server gave for key sets it has already made an account of. */
const registered = new WeakMap<AccountKeys, LoginResponse>()

/**
 * Create the account: the server answers with its session (the password was
 * registered with the keys, so no second sign-in). Safe to call again with
 * the same keys when activating failed: the account is created once.
 */
export async function registerAndSignIn(username: string, keys: AccountKeys, registrationCode?: string): Promise<void> {
  let data = registered.get(keys)
  if (!data) {
    const driveKeyBinding = await driveKeyBindingFor(keys, username)
    data = (
      await api.post<LoginResponse>('/auth/register', {
        username,
        ...(registrationCode ? { registrationCode } : {}),
        ...registrationBody(keys),
        driveKeyBinding,
      })
    ).data
    registered.set(keys, data)
  }
  await activate(data, { ...sessionKeys(keys), userId: data.userId })
}

/** First sign-in of an administrator-created account: store its new keys. */
export async function completeSetup(setup: PendingSetup, keys: AccountKeys): Promise<void> {
  const driveKeyBinding = await driveKeyBindingFor(keys, setup.username)
  const { data } = await api.post<LoginResponse>(
    '/auth/complete-setup',
    { ...registrationBody(keys), driveKeyBinding },
    { headers: { Authorization: `Bearer ${setup.setupToken}` } },
  )
  await activate(data, { ...sessionKeys(keys), userId: data.userId })
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
 * master key locally; the server receives a proof derived from it, which buys
 * a one-time grant to register the new password. Every session of the
 * account ends. (The phrase is the second factor, so 2FA is not asked.)
 */
export async function recoverAccount(name: string, mnemonic: string, newPassword: string): Promise<void> {
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
  try {
    const recoveryProof = await deriveRecoveryAuthProof(toBase64(recoveryKey), binding)
    const { data: granted } = await api.post<{ grant: string }>('/auth/recover/grant', { name, recoveryProof })
    await opaqueReregister(newPassword, binding, masterKey, granted.grant)
  } finally {
    masterKey.fill(0)
    recoveryKey.fill(0)
  }
}
