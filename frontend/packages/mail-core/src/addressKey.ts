import { DEFAULT_MAIL_KEY_FLAGS, generateMailAddressKey, signMailKeyList, toBase64 } from '@kutup/crypto'
import api from '@kutup/session/client'
import type { Session } from '@kutup/session/store'

/**
 * Generates an address's first key and publishes its first signed key list
 * (docs/plans/mail-address-keys.md). Run by the Account app at sign-in and
 * by Mail when it finds no key; two at once are safe: the server takes the
 * first key list and refuses the second (409).
 */
export async function addFirstAddressKey(session: Session, address: { id: string; address: string }) {
  const masterKey = toBase64(session.masterKey)
  const key = await generateMailAddressKey(masterKey, session.email, address.address)
  const list = await signMailKeyList(masterKey, {
    account: address.address,
    address: address.address,
    sequence: 1,
    issuedAt: new Date().toISOString(),
    keys: [{ fingerprint: key.fingerprint, sha256Fingerprint: key.sha256Fingerprint, primary: true, flags: DEFAULT_MAIL_KEY_FLAGS }],
  })
  await api.post(`/mail/addresses/${address.id}/keys`, {
    publicKey: key.publicKey,
    privateKeyEnvelope: key.envelope,
    keyList: { data: list.data, signature: list.signature },
  })
}
