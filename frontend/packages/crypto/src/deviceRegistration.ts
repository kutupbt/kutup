import { getCryptoWasm } from './rustWasm'

/**
 * The account's statement for a collaboration device
 * (`kutup_crypto::device_registration`, docs/plans/device-registration.md):
 * the account authority, derived from the master key, signs the server's
 * one-time challenge with the server, the account's user id, the device's
 * public key and the time. `POST /api/devices` (and `…/renew`) take it;
 * without it a session token alone cannot register a device.
 */
export async function signDeviceRegistration(
  masterKeyBase64: string,
  server: string,
  userId: string,
  devicePublicBase64: string,
  challengeBase64: string,
  issuedAtMs: number,
): Promise<string> {
  return (await getCryptoWasm()).signDeviceRegistration(
    masterKeyBase64,
    server,
    userId,
    devicePublicBase64,
    challengeBase64,
    issuedAtMs,
  )
}

/**
 * The account's revocation of a device key: `DELETE /api/devices/:id` takes
 * it, and other servers are told it, so a session alone cannot revoke the
 * account's devices.
 */
export async function signDeviceRevocation(
  masterKeyBase64: string,
  server: string,
  devicePublicBase64: string,
  revokedAtMs: number,
): Promise<string> {
  return (await getCryptoWasm()).signDeviceRevocation(masterKeyBase64, server, devicePublicBase64, revokedAtMs)
}
