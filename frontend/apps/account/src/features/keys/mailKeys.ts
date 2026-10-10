import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useRef } from 'react'
import {
  DEFAULT_MAIL_KEY_FLAGS,
  deriveAccountIdentityKeys,
  exportMailAddressKey,
  generateMailAddressKey,
  importMailAddressKey,
  MAIL_KEY_FLAGS,
  signMailKeyList,
  toBase64,
  verifyMailKeyList,
  type GeneratedMailAddressKey,
  type MailKeyEntry,
  type SignedMailKeyList,
} from '@kutup/crypto'
import { addFirstAddressKey } from '@kutup/mail-core/addressKey'
import api from '@kutup/session/client'
import { useRequiredSession, type Session } from '@kutup/session/store'

// The account's email addresses and their OpenPGP keys
// (docs/plans/mail-address-keys.md), as Proton's Settings → Encryption and
// keys shows them.

export interface MailKey {
  id: string
  fingerprint: string
  sha256Fingerprint: string
  publicKey: string
  privateKeyEnvelope: string
  primary: boolean
  flags: number
  createdAt: string
}

export interface MailAddress {
  id: string
  address: string
  keys: MailKey[]
  keyList: { data: string; signature: string } | null
}

export const mailAddressesKey = ['mail-addresses'] as const
export const createMailKeyMutation = ['mail-keys', 'create'] as const

/**
 * The caller's addresses, with each current key list checked against this
 * account's own authority: a list the account did not sign is reported, not
 * trusted.
 */
export function useMailAddresses() {
  const session = useRequiredSession()
  return useQuery({
    queryKey: mailAddressesKey,
    queryFn: async () => {
      const { data } = await api.get<MailAddress[]>('/mail/addresses')
      const { authorityPublicKey } = await deriveAccountIdentityKeys(toBase64(session.masterKey))
      return Promise.all(
        data.map(async (address) => ({
          ...address,
          verifiedList: address.keyList
            ? await verifyMailKeyList(address.keyList, authorityPublicKey).catch(() => null)
            : null,
        })),
      )
    },
  })
}

export type CheckedMailAddress = MailAddress & { verifiedList: SignedMailKeyList | null }

/**
 * Makes sure every address has a key, once per sign-in: new accounts get
 * theirs right after sign-up, existing accounts on their next visit. Two tabs
 * racing are safe: the server takes the first key list and refuses the
 * second (409), and the loser reloads to find the key there.
 */
export function useEnsureMailKeys() {
  const session = useRequiredSession()
  const queryClient = useQueryClient()
  const addresses = useMailAddresses()
  const started = useRef(new Set<string>())
  const add = useMutation({
    mutationKey: createMailKeyMutation,
    mutationFn: (address: MailAddress) => addFirstAddressKey(session, address),
    onSettled: () => queryClient.invalidateQueries({ queryKey: mailAddressesKey }),
    onError: (error) => console.warn('mail keys: could not create the address key', error),
  })
  useEffect(() => {
    for (const address of addresses.data ?? []) {
      if (address.keys.length > 0 || started.current.has(address.id)) continue
      started.current.add(address.id)
      add.mutate(address)
    }
  }, [addresses.data, add])
  return add
}

// --- Changing keys (docs/plans/mail.md, C3e) --------------------------------

/** The next key list after the address's current one, with `keys`, signed by this account. */
async function nextList(session: Session, address: CheckedMailAddress, keys: MailKeyEntry[]) {
  const current = address.verifiedList
  if (!current) throw new Error('the current key list is not signed by this account')
  return signMailKeyList(toBase64(session.masterKey), {
    account: current.account,
    address: current.address,
    sequence: current.sequence + 1,
    previousHash: current.hash,
    issuedAt: new Date().toISOString(),
    // Strictly by fingerprint (lowercase hex sorts as the bytes do).
    keys: [...keys].sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : 1)),
  })
}

function entries(address: CheckedMailAddress): MailKeyEntry[] {
  return address.keys.map((key) => ({ fingerprint: key.fingerprint, sha256Fingerprint: key.sha256Fingerprint, primary: key.primary, flags: key.flags }))
}

/** What a key list change does to one key. */
export type KeyChange =
  | { kind: 'makePrimary' }
  | { kind: 'obsolete'; on: boolean }
  | { kind: 'compromised'; on: boolean }

/** The keys after `change` to the key `fingerprint`. */
export function changedEntries(keys: MailKeyEntry[], fingerprint: string, change: KeyChange): MailKeyEntry[] {
  return keys.map((key) => {
    if (change.kind === 'makePrimary') return { ...key, primary: key.fingerprint === fingerprint }
    if (key.fingerprint !== fingerprint) return key
    if (change.kind === 'obsolete') {
      return { ...key, flags: change.on ? key.flags & ~MAIL_KEY_FLAGS.notObsolete : key.flags | MAIL_KEY_FLAGS.notObsolete }
    }
    // A compromised key is not encrypted to either (Proton clears both).
    return { ...key, flags: change.on ? 0 : key.flags | MAIL_KEY_FLAGS.notCompromised }
  })
}

function useKeyMutation<T>(fn: (input: T, session: Session) => Promise<unknown>) {
  const session = useRequiredSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: T) => fn(input, session),
    // Mail and the other apps read keys per session: they pick changes up on their next load.
    onSettled: () => queryClient.invalidateQueries({ queryKey: mailAddressesKey }),
  })
}

/** Makes a key primary, or marks it obsolete or compromised (or not), in a new key list. */
export function useChangeKey() {
  return useKeyMutation(async (input: { address: CheckedMailAddress; fingerprint: string; change: KeyChange }, session) => {
    const list = await nextList(session, input.address, changedEntries(entries(input.address), input.fingerprint, input.change))
    await api.put(`/mail/addresses/${input.address.id}/key-list`, { keyList: { data: list.data, signature: list.signature } })
  })
}

/** Adds a key (new, or imported), primary when asked; the other keys stay to open older mail. */
async function addKey(session: Session, address: CheckedMailAddress, key: GeneratedMailAddressKey, primary: boolean) {
  const keys = [
    ...entries(address).map((entry) => (primary ? { ...entry, primary: false } : entry)),
    { fingerprint: key.fingerprint, sha256Fingerprint: key.sha256Fingerprint, primary, flags: DEFAULT_MAIL_KEY_FLAGS },
  ]
  const list = await nextList(session, address, keys)
  await api.post(`/mail/addresses/${address.id}/keys`, {
    publicKey: key.publicKey,
    privateKeyEnvelope: key.envelope,
    keyList: { data: list.data, signature: list.signature },
  })
}

/** A new key for new mail (rotation). */
export function useNewKey() {
  return useKeyMutation(async (address: CheckedMailAddress, session) => {
    const key = await generateMailAddressKey(toBase64(session.masterKey), session.email, address.address)
    await addKey(session, address, key, true)
  })
}

/** Imports a key from an OpenPGP secret key file. `WrongKeyPassphrase` when the passphrase does not open it. */
export function useImportKey() {
  return useKeyMutation(async (input: { address: CheckedMailAddress; file: Uint8Array; passphrase: string; primary: boolean }, session) => {
    const key = await importMailAddressKey(toBase64(session.masterKey), session.email, input.address.address, input.file, input.passphrase)
    if (input.address.keys.some((k) => k.fingerprint === key.fingerprint)) throw new KeyAlreadyThere()
    await addKey(session, input.address, key, input.primary)
  })
}

/** The imported key is one of the address's keys already. */
export class KeyAlreadyThere extends Error {
  constructor() {
    super('this key is already one of the address keys')
  }
}

/** An address key as an armored file locked with `passphrase`. */
export async function exportKey(session: Session, address: string, key: MailKey, passphrase: string): Promise<string> {
  return exportMailAddressKey(
    { masterKeyBase64: toBase64(session.masterKey), loginEmail: session.email, address, envelope: key.privateKeyEnvelope, fingerprint: key.fingerprint },
    passphrase,
  )
}
