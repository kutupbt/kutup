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
 * What the account's own addresses say about `address` (folded), before a
 * rename to it makes its first key:
 * - `keyed`: a held (not freed) address of the account is it and has a key
 *   or a key list: no first key is made over it, whatever a check said;
 * - `freed`: the account's own freed row is it, with a key list: taking the
 *   name back must continue that chain (docs/plans/mail-address-keys.md),
 *   which isn't built yet, so the rename is refused for now;
 * - `none`: a first key at sequence 1.
 */
export async function ownAddressState(address: string): Promise<'keyed' | 'freed' | 'none'> {
  const folded = await foldAddress(address)
  const { data } = await api.get<{ address: string; state: string; keys: unknown[]; keyList: unknown }[]>('/mail/addresses')
  let state: 'keyed' | 'freed' | 'none' = 'none'
  for (const row of data) {
    if ((await foldAddress(row.address)) !== folded) continue
    if (row.state !== 'freed' && (row.keys.length > 0 || row.keyList !== null)) return 'keyed'
    if (row.state === 'freed' && row.keyList !== null) state = 'freed'
  }
  return state
}
