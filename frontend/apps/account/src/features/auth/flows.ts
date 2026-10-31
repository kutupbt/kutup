// The account app's sign-in flows. The crypto steps are the canonical ones
// from @kutup/crypto (OPAQUE in a worker, typed account envelopes); this
// file sequences them against the API and hands the unlocked keys to the
// session layer, which activates and persists them for this origin.

import {
  ACCOUNT_ENVELOPE_PURPOSE,
  driveKeysOf,
  generateAccountKeySet,
  openAccountEnvelope,
  rebindAccountKeySet,
  toBase64,
  deriveRecoveryAuthProof,
  type AccountKeySet,
} from '@kutup/crypto'
import { startOpaqueRegistration, type OpaqueRegistrar, type OpaqueSignIn } from '@kutup/crypto/opaqueWorker'
import { FIRST_DRIVE_KEY_BINDING_EPOCH, signDriveKeyBinding } from '@kutup/crypto/identityPins'
import { loadServerSettings } from '@kutup/session/apps'
import api from '@kutup/session/client'
import type { SessionKeys } from '@kutup/session/keys'
import {
  conflictCode,
  opaqueLogin,
  opaqueReregister,
  registerWith,
  reregisterWith,
  type RegistrationAuth,
} from '@kutup/session/opaque'
import { persistKeys } from '@kutup/session/persist'
import { activateSession } from '@kutup/session/profile'

interface LoginResponse {
  accessToken: string
  sessionId: string
  userId: string
  username: string
  masterKeyEnvelope: string
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

/**
 * A second factor is due. Holds the open sign-in (its worker holds the
 * password and the export key), never the password itself. End it with
 * {@link abandonTotp} when it is not completed.
 */
export interface TotpChallenge {
  name: string
  preAuthToken: string
  signIn: OpaqueSignIn
}

/** An administrator-created account signing in for the first time. */
export interface PendingSetup {
  name: string
  username: string
  /** The account's permanent id, which its new Drive key binding names. */
  accountId: string
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
  // The session layer also moves an account from before X-Wing Drive keys
  // to them (docs/plans/pq-shares.md): what it activated is what is kept.
  const activated = await activateSession(keys, response.accessToken, response.sessionId)
  await persistKeys(response.sessionId, activated)
}

/** This server's name: with an account id, who an account is (docs/plans/account-ids.md). */
async function serverName(): Promise<string> {
  const settings = await loadServerSettings<{ chat?: { serverName?: string | null } }>()
  const server = settings.chat?.serverName
  if (!server) throw new Error('the server did not publish its name')
  return server
}

/**
 * The account's Drive key binding (docs/plans/drive-identity-pins.md): its
 * authority vouching for its Drive keys as this account (its server and
 * permanent id, never its name), so the people it shares with can check
 * them. Sent with every new set of keys: a new account's first, at epoch 1.
 */
async function driveKeyBindingFor(keys: AccountKeys, accountId: string): Promise<string> {
  return signDriveKeyBinding(toBase64(keys.masterKey), { server: await serverName(), accountId }, FIRST_DRIVE_KEY_BINDING_EPOCH)
}

/**
 * Username (or Kutup address) + password, through OPAQUE: the password never
 * leaves this browser, and the master key's envelope comes only after the
 * server accepted the proof. An administrator-created account answers
 * `requiresSetup`; one with a second factor, `requiresTotp`.
 */
export async function signIn(name: string, password: string): Promise<SignInResult> {
  const { data, signIn: opened } = await opaqueLogin<LoginResponse>(password, { purpose: 'session', name })
  if (data.requiresSetup && data.setupToken) {
    opened.close()
    return { kind: 'setup', setup: { name, username: data.username, accountId: data.userId, setupToken: data.setupToken } }
  }
  if (data.requiresTotp && data.preAuthToken) {
    return { kind: 'totp', challenge: { name, preAuthToken: data.preAuthToken, signIn: opened } }
  }
  return finishSignIn(data, opened)
}

/** Opens the master key with the sign-in's export key, activates, and re-registers if the server asks. */
async function finishSignIn(data: LoginResponse, opened: OpaqueSignIn): Promise<SignInResult> {
  try {
    const binding = data.keyBinding
    if (!binding) throw new Error('the server did not say what the keys are bound to')
    // The master envelope opens only under its own binding, so once it has
    // opened the binding is verified.
    const masterKey = await opened.openMasterKey(data.masterKeyEnvelope, binding)
    // The Drive keys are derived from the master key, never stored
    // (docs/plans/w6-key-hierarchy.md §1); the server must publish the same.
    const { publicKey, privateKey } = await driveKeysOf(masterKey)
    if (publicKey !== data.publicKey) {
      privateKey.fill(0)
      throw new Error("the server publishes another Drive key than this account's")
    }
    await activate(data, { userId: data.userId, masterKey, privateKey, publicKey, keyBinding: binding })
    // A new server setup: the password just used (held by the sign-in's
    // worker) is registered again under it, without asking. A failure leaves
    // the old record, and the next sign-in asks again.
    if (data.rotate && data.grant) await reregisterWith(opened, binding, masterKey, data.grant).catch(() => undefined)
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
  return finishSignIn(data, challenge.signIn)
}

/** Ends a sign-in waiting for its second factor (the user went back, or left). Safe to call again. */
export function abandonTotp(challenge: TotpChallenge): void {
  challenge.signIn.close()
}

/**
 * Fresh account keys bound to a key binding drawn here, with the password
 * registered. `registrar` holds the password in its worker until
 * {@link releaseAccountKeys}, so a refused registration can be made again
 * without asking for it.
 */
export interface AccountKeys extends AccountKeySet {
  keyBinding: string
  opaqueRecord: string
  opaqueServerKeyId: number
  masterKeyEnvelope: string
  /** The id register/start minted for a sign-up, and its proof (none for a setup). */
  accountId?: string
  accountIdProof?: string
  registrar: OpaqueRegistrar
  auth: RegistrationAuth
}

/** The registration was refused twice for the same reason; the person can try again or start over. */
export class RegistrationConflictError extends Error {
  constructor(readonly code: 'opaqueKeyStale' | 'keyBindingTaken') {
    super(`registration refused: ${code}`)
    this.name = 'RegistrationConflictError'
  }
}

/**
 * Fresh account keys (master key, recovery phrase, envelopes, all bound to a
 * new key binding) and the password registered for them (OPAQUE; Argon2id in
 * a worker). `setupToken`: an administrator-created account's first sign-in.
 * A binding that turns out taken is drawn again, once.
 */
export async function generateAccountKeys(password: string, setupToken?: string): Promise<AccountKeys> {
  const auth: RegistrationAuth = setupToken ? { setupToken } : null
  const registrar = await startOpaqueRegistration(password)
  try {
    const draw = async () => {
      const keyBinding = crypto.randomUUID()
      const keys = await generateAccountKeySet(keyBinding)
      const registered = await registerWith(registrar, keyBinding, keys.masterKey, auth)
      return { ...keys, keyBinding, ...registered, registrar, auth }
    }
    try {
      return await draw()
    } catch (error) {
      if (conflictCode(error) !== 'keyBindingTaken') throw error
      return await draw()
    }
  } catch (error) {
    registrar.close()
    throw error
  }
}

/** Ends the worker holding the password of keys no longer needed (stored, or given up). */
export function releaseAccountKeys(keys: AccountKeys): void {
  keys.registrar.close()
}

/**
 * The same keys, ready to send again after the server refused them: a record
 * made under a server key that has since changed is made again; a key
 * binding someone else has meanwhile is drawn again (the records bound to it
 * sealed again; the recovery phrase stays).
 */
async function remade(keys: AccountKeys, code: string): Promise<AccountKeys> {
  if (code === 'opaqueKeyStale') {
    return { ...keys, ...(await registerWith(keys.registrar, keys.keyBinding, keys.masterKey, keys.auth)) }
  }
  const keyBinding = crypto.randomUUID()
  const resealed = await rebindAccountKeySet(keys, keyBinding)
  const registered = await registerWith(keys.registrar, keyBinding, keys.masterKey, keys.auth)
  return { ...keys, ...resealed, keyBinding, ...registered }
}

/**
 * Sends `keys` with `send`; refused as stale or for a taken binding, remakes
 * them and sends once more. The keys that were accepted come back with the
 * answer.
 */
async function sendKeys(keys: AccountKeys, send: (keys: AccountKeys) => Promise<LoginResponse>): Promise<{ data: LoginResponse; keys: AccountKeys }> {
  try {
    return { data: await send(keys), keys }
  } catch (error) {
    const code = conflictCode(error)
    if (code !== 'opaqueKeyStale' && code !== 'keyBindingTaken') throw error
    const again = await remade(keys, code)
    try {
      return { data: await send(again), keys: again }
    } catch (second) {
      const repeated = conflictCode(second)
      if (repeated === 'opaqueKeyStale' || repeated === 'keyBindingTaken') throw new RegistrationConflictError(repeated)
      throw second
    }
  }
}

function registrationBody(keys: AccountKeys) {
  return {
    keyBinding: keys.keyBinding,
    opaqueRecord: keys.opaqueRecord,
    opaqueServerKeyId: keys.opaqueServerKeyId,
    masterKeyEnvelope: keys.masterKeyEnvelope,
    recoveryKeyEnvelope: keys.recoveryKeyEnvelope,
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

/** Sessions the server gave for key sets it has already made an account of, with the keys it took. */
const registered = new WeakMap<AccountKeys, { data: LoginResponse; keys: AccountKeys }>()

/**
 * Create the account: the server answers with its session (the password was
 * registered with the keys, so no second sign-in). Safe to call again with
 * the same keys when activating failed: the account is created once.
 */
export async function registerAndSignIn(username: string, keys: AccountKeys, registrationCode?: string): Promise<void> {
  let done = registered.get(keys)
  if (!done) {
    done = await sendKeys(keys, async (sent) => {
      // The id register/start minted for these keys (a remade record has
      // its own), which the binding names.
      const { accountId, accountIdProof } = sent
      if (!accountId || !accountIdProof) throw new Error('the server gave no account id for the sign-up')
      return (
        await api.post<LoginResponse>('/auth/register', {
          username,
          ...(registrationCode ? { registrationCode } : {}),
          ...registrationBody(sent),
          accountId,
          accountIdProof,
          driveKeyBinding: await driveKeyBindingFor(sent, accountId),
        })
      ).data
    })
    registered.set(keys, done)
  }
  await activate(done.data, { ...sessionKeys(done.keys), userId: done.data.userId })
  releaseAccountKeys(keys)
}

/**
 * First sign-in of an administrator-created account: store its new keys.
 * Safe to call again with the same keys, as {@link registerAndSignIn}.
 */
export async function completeSetup(setup: PendingSetup, keys: AccountKeys): Promise<void> {
  let done = registered.get(keys)
  if (!done) {
    const driveKeyBinding = await driveKeyBindingFor(keys, setup.accountId)
    done = await sendKeys(keys, async (sent) =>
      (
        await api.post<LoginResponse>(
          '/auth/complete-setup',
          { ...registrationBody(sent), driveKeyBinding },
          { headers: { Authorization: `Bearer ${setup.setupToken}` } },
        )
      ).data,
    )
    registered.set(keys, done)
  }
  await activate(done.data, { ...sessionKeys(done.keys), userId: done.data.userId })
  releaseAccountKeys(keys)
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
