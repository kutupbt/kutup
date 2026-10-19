// The one-way identity suite upgrade (docs/plans/pq-shares.md), made where
// every app's session starts: a sign-in, a session handed to another app,
// and one restored from this browser.

import { isAxiosError } from 'axios'
import { currentDriveKeys, deriveAccountIdentityKeys, fromBase64, toBase64 } from '@kutup/crypto'
import { FIRST_DRIVE_KEY_BINDING_EPOCH, signDriveKeyBinding } from '@kutup/crypto/identityPins'
import api from './client'
import type { SessionKeys } from './keys'

/** What the upgrade needs to know of the account, from `/user/me`. */
export interface IdentitySuiteProfile {
  id: string
  /** This server's name: with `id`, who the account is. */
  server?: string
  /** The Drive key the server publishes for the account now. */
  publicKey: string
}

/**
 * The account's keys on identity suite 2 (X-Wing Drive keys). An account
 * whose server still publishes another key than the X-Wing one its master
 * key derives moves now, once: the upgrade at its last sign-in failed, or
 * this session is older than the upgrade. It happens before any app uses the
 * keys, so Chat never starts with a manifest the server refuses. Another
 * device that upgraded first (`identitySuiteCurrent`) published the same
 * keys. Any failure (the derivation, the request) keeps the keys as they
 * are: the session starts, and the next session start tries again.
 */
export async function upgradedKeys(keys: SessionKeys, me: IdentitySuiteProfile, accessToken: string): Promise<SessionKeys> {
  try {
    const identity = await deriveAccountIdentityKeys(toBase64(keys.masterKey))
    const publicKey = identity.driveHpkePublicKey
    if (me.publicKey === publicKey) {
      // The server is current; this session may hold keys from before.
      if (keys.publicKey === publicKey) return keys
      const previous = keys.privateKey
      const upgraded = { ...keys, publicKey, privateKey: fromBase64(identity.driveHpkePrivateKey) }
      previous.fill(0)
      return upgraded
    }
    if (!me.server) return keys
    // Only now the private key is sealed for the server.
    const drive = await currentDriveKeys(keys.masterKey, keys.keyBinding)
    const driveKeyBinding = await signDriveKeyBinding(
      toBase64(keys.masterKey),
      { server: me.server, accountId: me.id },
      FIRST_DRIVE_KEY_BINDING_EPOCH,
    )
    try {
      // The session isn't active yet: its token goes with this request alone.
      await api.post(
        '/account/identity-suite',
        {
          publicKey: drive.publicKey,
          driveKeyBinding,
          driveKeyBindingEpoch: FIRST_DRIVE_KEY_BINDING_EPOCH,
          drivePrivateKeyEnvelope: drive.drivePrivateKeyEnvelope,
        },
        { headers: { Authorization: `Bearer ${accessToken}` } },
      )
    } catch (error) {
      const code = isAxiosError(error) && error.response?.status === 409
        ? (error.response.data as { code?: string } | undefined)?.code
        : undefined
      if (code !== 'identitySuiteCurrent') {
        drive.privateKey.fill(0)
        return keys
      }
    }
    const previous = keys.privateKey
    const upgraded = { ...keys, publicKey: drive.publicKey, privateKey: drive.privateKey }
    previous.fill(0)
    return upgraded
  } catch {
    return keys
  }
}
