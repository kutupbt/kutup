import { DEFAULT_MAIL_KEY_FLAGS, foldAddress, generateMailAddressKey, signMailKeyList, toBase64 } from '@kutup/crypto'
import api from '@kutup/session/client'
import type { Session } from '@kutup/session/store'

/**
 * An address's first key and its first signed key list (sequence 1, that key
 * primary), as `POST /api/mail/addresses/{id}/keys` and a rename's
 * `mailAddress` take them.
 */
export interface FirstAddressKey {
  publicKey: string
  privateKeyEnvelope: string
  keyList: { data: string; signature: string }
}

/** Generates the first key of `address` and signs its first key list. */
export async function firstAddressKey(session: Pick<Session, 'masterKey' | 'envelopeBinding'>, address: string): Promise<FirstAddressKey> {
  const masterKey = toBase64(session.masterKey)
  const key = await generateMailAddressKey(masterKey, session.envelopeBinding, address)
  const list = await signMailKeyList(masterKey, {
    address,
    sequence: 1,
    issuedAt: new Date().toISOString(),
    keys: [{ fingerprint: key.fingerprint, sha256Fingerprint: key.sha256Fingerprint, primary: true, flags: DEFAULT_MAIL_KEY_FLAGS }],
  })
  return {
    publicKey: key.publicKey,
    privateKeyEnvelope: key.envelope,
    keyList: { data: list.data, signature: list.signature },
  }
}

/**
 * Generates an address's first key and publishes its first signed key list
 * (docs/plans/mail-address-keys.md). Run by the Account app at sign-in and
 * by Mail when it finds no key; two at once are safe: the server takes the
 * first key list and refuses the second (409).
 */
export async function addFirstAddressKey(session: Session, address: { id: string; address: string }) {
  await api.post(`/mail/addresses/${address.id}/keys`, await firstAddressKey(session, address.address))
}

/**
 * Whether one of the account's own addresses is `address` (folded) and has
 * a key or a key list already: then no first key is made for it, whatever a
 * check said, so a server can't have a fresh first list signed over a chain
 * the address has.
 */
export async function ownAddressKeyed(address: string): Promise<boolean> {
  const folded = await foldAddress(address)
  const { data } = await api.get<{ address: string; keys: unknown[]; keyList: unknown }[]>('/mail/addresses')
  for (const row of data) {
    if ((await foldAddress(row.address)) === folded && (row.keys.length > 0 || row.keyList !== null)) return true
  }
  return false
}
