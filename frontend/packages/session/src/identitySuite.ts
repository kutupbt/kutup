// The one-way identity suite upgrade (docs/plans/pq-shares.md), made where
// every app's session starts: a sign-in, a session handed to another app,
// and one restored from this browser.

import { isAxiosError } from 'axios'
import { currentDriveKeys, toBase64 } from '@kutup/crypto'
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
 * keys. A failure keeps the keys as they are, and the next session start
 * tries again.
 */
export async function upgradedKeys(keys: SessionKeys, me: IdentitySuiteProfile, accessToken: string): Promise<SessionKeys> {
  const drive = await currentDriveKeys(keys.masterKey, keys.keyBinding)
  const current = (): SessionKeys => {
    if (drive.publicKey === keys.publicKey) {
      drive.privateKey.fill(0)
      return keys
    }
    keys.privateKey.fill(0)
    return { ...keys, publicKey: drive.publicKey, privateKey: drive.privateKey }
  }
  if (me.publicKey === drive.publicKey) return current()
  if (!me.server) {
    drive.privateKey.fill(0)
    return keys
  }
  try {
    const driveKeyBinding = await signDriveKeyBinding(
      toBase64(keys.masterKey),
      { server: me.server, accountId: me.id },
      FIRST_DRIVE_KEY_BINDING_EPOCH,
    )
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
  return current()
}
