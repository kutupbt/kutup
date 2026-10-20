import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useRef } from 'react'
import {
  DEFAULT_MAIL_KEY_FLAGS,
  exportMailAddressKey,
  generateMailAddressKey,
  importMailAddressKey,
  MAIL_KEY_FLAGS,
  toBase64,
  type GeneratedMailAddressKey,
  type MailKeyEntry,
  type SignedMailKeyList,
} from '@kutup/crypto'
import { addFirstAddressKey } from '@kutup/mail-core/addressKey'
import { checkedAddresses, nextKeyList, signedEntries, signedEntry, type CheckedKey } from '@kutup/mail-core/keyList'
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
 * The caller's addresses, each checked against this account's own authority
 * (`checkedAddresses`): a list the account did not sign, one for another
 * address, or one older than this device has seen is reported, not trusted;
 * a key row is the account's only when its public key has the fingerprints
 * a signed entry names.
 */
export function useMailAddresses() {
  const session = useRequiredSession()
  return useQuery({
    queryKey: mailAddressesKey,
    queryFn: async (): Promise<CheckedMailAddress[]> => checkedAddresses(session, (await api.get<MailAddress[]>('/mail/addresses')).data),
  })
}

export type CheckedMailAddress = Omit<MailAddress, 'keys'> & { keys: CheckedKey<MailKey>[]; verifiedList: SignedMailKeyList | null }

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
    mutationFn: (address: { id: string; address: string }) => addFirstAddressKey(session, address),
    onSettled: () => queryClient.invalidateQueries({ queryKey: mailAddressesKey }),
    onError: (error) => console.warn('mail keys: could not create the address key', error),
  })
  useEffect(() => {
    for (const address of addresses.data ?? []) {
      // Only an address with no key and no key list: a server that drops the
      // rows of a keyed address can't have a fresh first list signed.
      if (address.keys.length > 0 || address.keyList !== null || started.current.has(address.id)) continue
      started.current.add(address.id)
      add.mutate(address)
    }
  }, [addresses.data, add])
  return add
}

// --- Changing keys (docs/plans/mail.md, C3e) --------------------------------
//
// Every change starts from the key list this account signed
// (`signedEntries`), never from the server's rows: a key, primary or flag the
// server lists on its own is never signed into the next list.

/** What a key list change does to one key. */
export type KeyChange =
  | { kind: 'makePrimary' }
  | { kind: 'obsolete'; on: boolean }
  | { kind: 'compromised'; on: boolean }

/** The keys after `change` to the key `fingerprint`, which must be one of them. */
export function changedEntries(keys: MailKeyEntry[], fingerprint: string, change: KeyChange): MailKeyEntry[] {
  if (!keys.some((key) => key.fingerprint === fingerprint)) throw new KeyNotInList()
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
    const list = await nextKeyList(session, input.address, changedEntries(signedEntries(input.address), input.fingerprint, input.change))
    await api.put(`/mail/addresses/${input.address.id}/key-list`, { keyList: { data: list.data, signature: list.signature } })
  })
}

/** The signed keys with `key` added, primary when asked; the others stay to open older mail. */
export function entriesWithKey(signed: MailKeyEntry[], key: Pick<GeneratedMailAddressKey, 'fingerprint' | 'sha256Fingerprint'>, primary: boolean): MailKeyEntry[] {
  if (signed.some((entry) => entry.fingerprint === key.fingerprint)) throw new KeyAlreadyThere()
  return [
    ...signed.map((entry) => (primary ? { ...entry, primary: false } : entry)),
    { fingerprint: key.fingerprint, sha256Fingerprint: key.sha256Fingerprint, primary, flags: DEFAULT_MAIL_KEY_FLAGS },
  ]
}

/** Adds a key (new, or imported), primary when asked. */
async function addKey(session: Session, address: CheckedMailAddress, key: GeneratedMailAddressKey, primary: boolean) {
  const list = await nextKeyList(session, address, entriesWithKey(signedEntries(address), key, primary))
  await api.post(`/mail/addresses/${address.id}/keys`, {
    publicKey: key.publicKey,
    privateKeyEnvelope: key.envelope,
    keyList: { data: list.data, signature: list.signature },
  })
}

/** A new key for new mail (rotation). */
export function useNewKey() {
  return useKeyMutation(async (address: CheckedMailAddress, session) => {
    const key = await generateMailAddressKey(toBase64(session.masterKey), session.envelopeBinding, address.address)
    await addKey(session, address, key, true)
  })
}

/** Imports a key from an OpenPGP secret key file. `WrongKeyPassphrase` when the passphrase does not open it. */
export function useImportKey() {
  return useKeyMutation(async (input: { address: CheckedMailAddress; file: Uint8Array; passphrase: string; primary: boolean }, session) => {
    const key = await importMailAddressKey(toBase64(session.masterKey), session.envelopeBinding, input.address.address, input.file, input.passphrase)
    if (input.address.keys.some((k) => k.fingerprint === key.fingerprint)) throw new KeyAlreadyThere()
    await addKey(session, input.address, key, input.primary)
  })
}

/** The key isn't in the address's signed key list: the server listed it on its own. */
export class KeyNotInList extends Error {
  constructor() {
    super('this key is not in the key list this account signed')
  }
}

/**
 * A key as this account's signed list has it: its primary and flags are the
 * list's, never the server's. Null when the list doesn't have it.
 */
export function asSigned(address: CheckedMailAddress, key: CheckedKey<MailKey>): CheckedKey<MailKey> | null {
  const entry = signedEntry(address, key.fingerprint)
  if (!key.listed || !entry || entry.sha256Fingerprint !== key.sha256Fingerprint) return null
  return { ...key, primary: entry.primary, flags: entry.flags }
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
    { masterKeyBase64: toBase64(session.masterKey), binding: session.envelopeBinding, address, envelope: key.privateKeyEnvelope, fingerprint: key.fingerprint },
    passphrase,
  )
}
