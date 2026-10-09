import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  deriveAccountIdentityKeys,
  openContactCard,
  sealContactCard,
  signContactSummary,
  toBase64,
  verifyContactSummary,
  type ContactSummary,
} from '@kutup/crypto'
import api from '@kutup/session/client'
import { updateSession, useRequiredSession, type Session } from '@kutup/session/store'
import { displayName, newUid, type Contact, type ContactDraft, type ContactGroup } from './model'
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
    // The signed summary is authoritative for what it holds.
    const draft = { ...card.draft, name: summary.name, groups: summary.groups }
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
    queryFn: async () => {
      const masterKey = toBase64(session.masterKey)
      const { authorityPublicKey } = await deriveAccountIdentityKeys(masterKey)
      const rows: ContactRow[] = []
      for (let offset = 0; ; ) {
        const { data } = await api.get<{ contacts: ContactRow[]; total: number }>('/contacts', { params: { offset, limit: 1000 } })
        rows.push(...data.contacts)
        offset += data.contacts.length
        if (data.contacts.length === 0 || offset >= data.total) break
      }
      const opened = await Promise.all(rows.map((row) => openRow(row, account.data!, masterKey, authorityPublicKey)))
      const contacts = opened.filter((contact): contact is Contact => contact !== null)
      return { contacts, unreadable: rows.length - contacts.length }
    },
  })
}

function summaryOf(uid: string, draft: ContactDraft): ContactSummary {
  const seen = new Set<string>()
  const emails = draft.emails
    .map((email) => ({ address: email.address.trim().toLowerCase(), label: email.label?.trim() || undefined }))
    .filter((email) => email.address && !seen.has(email.address) && seen.add(email.address))
  return { uid, name: displayName(draft), emails, groups: [...new Set(draft.groups)].sort(), pinnedKeys: [] }
}

/** The request body for a contact: signed summary and sealed card. */
async function prepare(session: Session, account: string, uid: string, draft: ContactDraft) {
  const masterKey = toBase64(session.masterKey)
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

export interface ContactEmailMatch {
  contactId: string
  name: string
  address: string
  label: string | null
}

/** Addresses matching `q` (name or address), for recipient and share pickers. */
export function useContactEmailSearch(q: string, enabled = true) {
  return useQuery({
    queryKey: ['contacts', 'emails', q],
    enabled,
    staleTime: 30_000,
    queryFn: async () => (await api.get<ContactEmailMatch[]>('/contacts/emails', { params: { q, limit: 20 } })).data,
  })
}
