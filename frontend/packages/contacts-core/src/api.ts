import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useCallback, useMemo } from 'react'
import {
  deriveAccountIdentityKeys,
  describeExternalMailKey,
  fromBase64,
  openContactCard,
  sealContactCard,
  signContactSummary,
  toBase64,
  verifyContactSummary,
  type ContactSummary,
} from '@kutup/crypto'
import api from '@kutup/session/client'
import { updateSession, useRequiredSession, type Session } from '@kutup/session/store'
import { displayName, emptyDraft, newUid, type Contact, type ContactDraft, type ContactGroup, type ContactKey } from './model'
import { parseVCards, toVCard } from './vcard'

// The account's address book (docs/plans/contacts.md): summaries verified
// against the account's own authority, cards opened with the contacts key.

interface ContactRow {
  id: string
  summary: string
  signature: string
  card: string
  revision: number
  updatedAt: string
}

export const contactsKey = ['contacts'] as const
export const contactGroupsKey = ['contacts', 'groups'] as const

/** The account's routing address (`username@server`), which binds every contact. */
export function useAccountAddress() {
  const session = useRequiredSession()
  return useQuery({
    queryKey: ['account-address', session.sessionId],
    staleTime: Infinity,
    queryFn: async () => {
      const { data } = await api.get<{ chat?: { serverName?: string } }>('/auth/settings')
      const server = data.chat?.serverName
      if (!server || !session.username) throw new Error('this account has no address yet')
      return `${session.username}@${server}`
    },
  })
}

async function openRow(row: ContactRow, account: string, masterKey: string, authority: string): Promise<Contact | null> {
  try {
    const summary = await verifyContactSummary(row.summary, row.signature, account, authority)
    const vcard = await openContactCard(masterKey, account, summary.uid, row.card)
    const [card] = parseVCards(vcard)
    if (!card) return null
    // The signed summary is authoritative for what it holds: a pinned key
    // counts only when the summary names its fingerprint, with its flags.
    const keys = (await withFingerprints(card.draft.keys)).flatMap((key) => {
      const pinned = summary.pinnedKeys.find((p) => p.address === key.address && p.fingerprint === key.fingerprint)
      return pinned ? [{ ...key, encrypt: pinned.encrypt, sign: pinned.sign }] : []
    })
    const draft = { ...card.draft, name: summary.name, groups: summary.groups, keys }
    return { id: row.id, uid: summary.uid, revision: row.revision, draft, updatedAt: row.updatedAt }
  } catch (error) {
    console.warn('contacts: a contact did not verify or open', row.id, error)
    return null
  }
}

/**
 * Every contact, verified and opened, by name. A contact whose summary this
 * account did not sign, or whose card does not open, is left out and counted.
 */
export function useContacts() {
  const session = useRequiredSession()
  const account = useAccountAddress()
  return useQuery({
    queryKey: contactsKey,
    enabled: account.isSuccess,
    queryFn: () => loadContacts(session, account.data!),
  })
}

async function loadContacts(session: Session, account: string): Promise<{ contacts: Contact[]; unreadable: number }> {
  const masterKey = toBase64(session.masterKey)
  const { authorityPublicKey } = await deriveAccountIdentityKeys(masterKey)
  const rows: ContactRow[] = []
  for (let offset = 0; ; ) {
    const { data } = await api.get<{ contacts: ContactRow[]; total: number }>('/contacts', { params: { offset, limit: 1000 } })
    rows.push(...data.contacts)
    offset += data.contacts.length
    if (data.contacts.length === 0 || offset >= data.total) break
  }
  const opened = await Promise.all(rows.map((row) => openRow(row, account, masterKey, authorityPublicKey)))
  const contacts = opened.filter((contact): contact is Contact => contact !== null)
  return { contacts, unreadable: rows.length - contacts.length }
}

/** Most pinned keys one contact may have (kutup-crypto `MAX_PINNED_KEYS`). */
const MAX_PINNED_KEYS = 20

/** Keys with their fingerprints, read from the keys themselves; keys that do not parse are dropped. */
async function withFingerprints(keys: ContactKey[]): Promise<ContactKey[]> {
  const read = await Promise.all(
    keys.map(async (key) => {
      try {
        const info = await describeExternalMailKey(fromBase64(key.publicKey))
        return { ...key, address: key.address.toLowerCase(), publicKey: info.publicKey, fingerprint: info.fingerprint }
      } catch {
        return null
      }
    }),
  )
  return read.filter((key): key is ContactKey => key !== null)
}

function summaryOf(uid: string, draft: ContactDraft): ContactSummary {
  const seen = new Set<string>()
  const emails = draft.emails
    .map((email) => ({ address: email.address.trim().toLowerCase(), label: email.label?.trim() || undefined }))
    .filter((email) => email.address && !seen.has(email.address) && seen.add(email.address))
  const pinnedKeys = draft.keys
    .filter((key) => seen.has(key.address) && key.fingerprint)
    .map(({ address, fingerprint, encrypt, sign }) => ({ address, fingerprint, encrypt, sign }))
    .sort((a, b) => (a.address === b.address ? a.fingerprint.localeCompare(b.fingerprint) : a.address < b.address ? -1 : 1))
    .slice(0, MAX_PINNED_KEYS)
  return { uid, name: displayName(draft), emails, groups: [...new Set(draft.groups)].sort(), pinnedKeys }
}

/** The request body for a contact: signed summary and sealed card. */
async function prepare(session: Session, account: string, uid: string, input: ContactDraft) {
  const masterKey = toBase64(session.masterKey)
  // One key per address that is still among the emails.
  const addresses = new Set(input.emails.map((email) => email.address.trim().toLowerCase()))
  const keys = (await withFingerprints(input.keys)).filter(
    (key, i, all) => addresses.has(key.address) && all.findIndex((k) => k.address === key.address) === i,
  )
  const draft = { ...input, keys }
  const summary = summaryOf(uid, draft)
  const signed = await signContactSummary(masterKey, account, summary)
  const card = await sealContactCard(masterKey, account, uid, toVCard({ ...draft, groups: summary.groups }, uid, summary.name))
  return { summary: signed.summary, signature: signed.signature, card }
}

function useContactMutation<T, R>(fn: (input: T, session: Session, account: string) => Promise<R>) {
  const session = useRequiredSession()
  const account = useAccountAddress()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (input: T) => {
      if (!account.data) throw new Error('this account has no address yet')
      return fn(input, session, account.data)
    },
    onSettled: () =>
      Promise.all([
        queryClient.invalidateQueries({ queryKey: contactsKey }),
        // Contacts count against the storage pool (drive-core storageKey),
        // and the sidebar meter reads the session's figure.
        queryClient.invalidateQueries({ queryKey: ['storage'] }),
        api
          .get<{ storageUsedBytes: number }>('/user/me')
          .then(({ data }) => updateSession({ storageUsedBytes: data.storageUsedBytes }))
          .catch(() => undefined),
      ]),
  })
}

/** Creates a contact, or saves an edit made from `revision`. */
export function useSaveContact() {
  return useContactMutation(
    async (input: { draft: ContactDraft; existing?: Pick<Contact, 'id' | 'uid' | 'revision'> }, session, account) => {
      const uid = input.existing?.uid ?? newUid()
      const body = await prepare(session, account, uid, input.draft)
      if (input.existing) {
        const { data } = await api.put<ContactRow>(`/contacts/${input.existing.id}`, { ...body, revision: input.existing.revision })
        return data.id
      }
      const { data } = await api.post<ContactRow>('/contacts', body)
      return data.id
    },
  )
}

export function useDeleteContacts() {
  return useContactMutation(async (ids: string[], _session, _account) => {
    for (let i = 0; i < ids.length; i += 500) {
      await api.post('/contacts/delete', { ids: ids.slice(i, i + 500) })
    }
  })
}

/**
 * Imports drafts in batches of 500 (each batch all or nothing). Cards keep
 * their own UID unless the address book already has it.
 */
export function useImportContacts() {
  return useContactMutation(
    async (input: { cards: { uid?: string; draft: ContactDraft }[]; takenUids: Set<string> }, session, account) => {
      let imported = 0
      for (let i = 0; i < input.cards.length; i += 500) {
        const batch = input.cards.slice(i, i + 500)
        const contacts = await Promise.all(
          batch.map(({ uid, draft }) => {
            const ownUid = uid && !input.takenUids.has(uid) && uid.length <= 200 ? uid : newUid()
            input.takenUids.add(ownUid)
            return prepare(session, account, ownUid, draft)
          }),
        )
        await api.post('/contacts/import', { contacts })
        imported += batch.length
      }
      return imported
    },
  )
}

export function useContactGroups() {
  return useQuery({
    queryKey: contactGroupsKey,
    queryFn: async () => (await api.get<ContactGroup[]>('/contacts/groups')).data,
  })
}

export function useSaveGroup() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (input: { id?: string; name: string; color: string }) => {
      if (input.id) await api.put(`/contacts/groups/${input.id}`, { name: input.name, color: input.color })
      else await api.post('/contacts/groups', { name: input.name, color: input.color })
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: contactGroupsKey }),
  })
}

export function useDeleteGroup() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/contacts/groups/${id}`)
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: contactGroupsKey }),
  })
}

/**
 * Pins `publicKey` (binary, base64) for `address`: on the contact that has
 * the address, or on a new contact named after it (docs/plans/mail.md, C3;
 * a key is pinned only at the person's request). Replaces a key pinned
 * there before.
 */
export function usePinKey() {
  const queryClient = useQueryClient()
  return useContactMutation(
    async (input: { address: string; name?: string; publicKey: string }, session, account) => {
      const address = input.address.trim().toLowerCase()
      const key: ContactKey = { address, publicKey: input.publicKey, fingerprint: '', encrypt: true, sign: true }
      // Fresh, so the key lands on the contact as it is now.
      const { contacts } = await queryClient.fetchQuery({ queryKey: contactsKey, queryFn: () => loadContacts(session, account) })
      const existing = contacts.find((c) => c.draft.emails.some((e) => e.address.trim().toLowerCase() === address))
      if (existing) {
        const draft = { ...existing.draft, keys: [...existing.draft.keys.filter((k) => k.address !== address), key] }
        const body = await prepare(session, account, existing.uid, draft)
        await api.put(`/contacts/${existing.id}`, { ...body, revision: existing.revision })
        return
      }
      const draft: ContactDraft = { ...emptyDraft(), name: input.name?.trim() ?? '', emails: [{ address }], keys: [key] }
      await api.post('/contacts', await prepare(session, account, newUid(), draft))
    },
  )
}

/**
 * Finds the contact that has an address, from the opened address book
 * (undefined while it loads or when nobody has it). Mail uses it to name
 * senders and to offer saving the ones who are not there yet.
 */
export function useContactLookup(): { ready: boolean; find: (address: string | undefined | null) => Contact | undefined } {
  const contacts = useContacts()
  const byAddress = useMemo(() => {
    const map = new Map<string, Contact>()
    for (const contact of contacts.data?.contacts ?? []) {
      for (const email of contact.draft.emails) {
        const address = email.address.trim().toLowerCase()
        if (address && !map.has(address)) map.set(address, contact)
      }
    }
    return map
  }, [contacts.data])
  const find = useCallback((address: string | undefined | null) => (address ? byAddress.get(address.trim().toLowerCase()) : undefined), [byAddress])
  return { ready: contacts.isSuccess, find }
}

/**
 * Adds an address to a contact that is already in the address book (Proton's
 * "add to existing contact"), giving it a name when it had none. Read fresh,
 * so the edit lands on the contact as it is now.
 */
export function useAddEmailToContact() {
  const queryClient = useQueryClient()
  return useContactMutation(async (input: { contactId: string; address: string; name?: string }, session, account) => {
    const address = input.address.trim().toLowerCase()
    const { contacts } = await queryClient.fetchQuery({ queryKey: contactsKey, queryFn: () => loadContacts(session, account) })
    const existing = contacts.find((c) => c.id === input.contactId)
    if (!existing) throw new Error('this contact no longer exists')
    if (existing.draft.emails.some((e) => e.address.trim().toLowerCase() === address)) return existing.id
    const draft: ContactDraft = {
      ...existing.draft,
      name: existing.draft.name.trim() || existing.draft.givenName || existing.draft.familyName ? existing.draft.name : (input.name?.trim() ?? ''),
      emails: [...existing.draft.emails, { address }],
    }
    const body = await prepare(session, account, existing.uid, draft)
    await api.put(`/contacts/${existing.id}`, { ...body, revision: existing.revision })
    return existing.id
  })
}

export { useContactEmailSearch, type ContactEmailMatch } from './search'

