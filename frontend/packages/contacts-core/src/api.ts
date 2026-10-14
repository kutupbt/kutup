import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import { useCallback, useMemo } from 'react'
import {
  deriveAccountIdentityKeys,
  describeExternalMailKey,
  fromBase64,
  openContactCard,
  revisionGuard,
  sealContactCard,
  signContactSummary,
  toBase64,
  verifyContactSummary,
  type ContactSummary,
} from '@kutup/crypto'
import {
  accountHead,
  HeadBlockedError,
  NotInVerifiedIndexError,
  type ListedEdit,
  type VerifiedIndex,
} from '@kutup/session/accountHead'
import api from '@kutup/session/client'
import { updateSession, useRequiredSession, type Session } from '@kutup/session/store'
import { displayName, emptyDraft, pgpFor, newUid, type Contact, type ContactDraft, type ContactGroup, type ContactKey } from './model'
import { parseVCards, toVCard } from './vcard'

// The account's address book (docs/plans/contacts.md): summaries verified
// against the account's own authority, cards opened with the contacts key,
// both bound to the account's key binding (`session.envelopeBinding`), never
// to its address. Both carry the contact's revision: a contact older than
// this browser has seen is refused (`RevisionGuard`), and an edit is stored
// only on top of the revision it started from (`baseRevision`; a 409 means
// another device saved first).

/** What the guard calls a contact: its UID, which a re-import keeps. */
const CONTACT_SCOPE = 'contact'

/**
 * The address book is the account head's `contacts` scope
 * (docs/plans/rollback-protection.md), its values named by UID: chosen here,
 * unique per account, never changed, so a head can be made before a create.
 */
const HEAD_SCOPE = 'contacts'

/**
 * The head's index of the address book, or null when it cannot vouch (this
 * app is blocked on another history: reads go on, held to this browser's own
 * guard, and the banner says why).
 */
async function contactsIndex(session: Session): Promise<VerifiedIndex | null> {
  try {
    return await (await accountHead(session)).verifiedIndex(HEAD_SCOPE)
  } catch (error) {
    if (error instanceof HeadBlockedError) return null
    throw error
  }
}

/** A listed write of the address book, with the next account head. */
async function listedContacts<T>(session: Session, edit: (index: VerifiedIndex) => Promise<ListedEdit<T> | null>): Promise<T | undefined> {
  return (await accountHead(session)).listedWrite(HEAD_SCOPE, edit)
}

/**
 * Another device changed the contact since the edit started (the server's
 * `revision_conflict`, or the head's index listing another revision): the
 * person's form is not laid over it.
 */
export class ContactChangedError extends Error {
  constructor() {
    super('the contact was changed elsewhere')
    this.name = 'ContactChangedError'
  }
}

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

/** The account's routing address (`username@server`). */
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

async function openRow(
  session: Session,
  row: ContactRow,
  masterKey: string,
  authority: string,
  index: VerifiedIndex | null,
): Promise<Contact | null> {
  const binding = session.envelopeBinding
  try {
    // The server says which revision the card is; the summary's signature
    // and the card's header must both agree with it.
    const summary = await verifyContactSummary(row.summary, row.signature, binding, row.revision, authority)
    const { value: vcard, revision } = await openContactCard(masterKey, binding, summary.uid, row.card)
    if (revision !== row.revision) throw new Error('the card is not the revision its summary was signed for')
    // Not the revision the account head vouches for: rolled back, or brought back.
    index?.expect(summary.uid, revision)
    await revisionGuard(session).accept(CONTACT_SCOPE, summary.uid, revision)
    const [card] = parseVCards(vcard)
    if (!card) return null
    // The signed summary is authoritative for what it holds: a trusted key
    // counts only when the summary names its fingerprint.
    const keys = (await withFingerprints(card.draft.keys)).filter((key) =>
      summary.pinnedKeys.some((p) => p.address === key.address && p.fingerprint === key.fingerprint),
    )
    const draft = { ...card.draft, name: summary.name, groups: summary.groups, keys }
    return { id: row.id, uid: summary.uid, revision: row.revision, draft, updatedAt: row.updatedAt }
  } catch (error) {
    if (error instanceof NotInVerifiedIndexError) throw error
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
  return useQuery({
    queryKey: contactsKey,
    queryFn: () => loadContacts(session),
  })
}

export async function loadContacts(session: Session): Promise<{ contacts: Contact[]; unreadable: number }> {
  const masterKey = toBase64(session.masterKey)
  const { authorityPublicKey } = await deriveAccountIdentityKeys(masterKey)
  // The book and the head's index are two reads: a write landing between
  // them is read again once before the book counts as one the head does not
  // vouch for (then nothing of it is shown).
  for (let attempt = 0; ; attempt++) {
    const index = await contactsIndex(session)
    const rows: ContactRow[] = []
    for (let offset = 0; ; ) {
      const { data } = await api.get<{ contacts: ContactRow[]; total: number }>('/contacts', { params: { offset, limit: 1000 } })
      rows.push(...data.contacts)
      offset += data.contacts.length
      if (data.contacts.length === 0 || offset >= data.total) break
    }
    try {
      // One more or fewer than the head lists: dropped, or brought back.
      if (index?.covered && rows.length !== index.values.length) throw new NotInVerifiedIndexError(HEAD_SCOPE, null)
      const opened = await Promise.all(rows.map((row) => openRow(session, row, masterKey, authorityPublicKey, index)))
      const contacts = opened.filter((contact): contact is Contact => contact !== null)
      return { contacts, unreadable: rows.length - contacts.length }
    } catch (error) {
      if (!(error instanceof NotInVerifiedIndexError) || attempt > 0) throw error
    }
  }
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
  // Each trusted key with its address's preferences (unset: encrypt, and sign as the account does).
  const pinnedKeys = draft.keys
    .filter((key) => seen.has(key.address) && key.fingerprint)
    .map(({ address, fingerprint }) => {
      const pgp = pgpFor(draft, address)
      return { address, fingerprint, encrypt: pgp.encrypt ?? true, sign: pgp.encrypt === true || (pgp.sign ?? true) }
    })
    .sort((a, b) => (a.address === b.address ? a.fingerprint.localeCompare(b.fingerprint) : a.address < b.address ? -1 : 1))
    .slice(0, MAX_PINNED_KEYS)
  return { uid, name: displayName(draft), emails, groups: [...new Set(draft.groups)].sort(), pinnedKeys }
}

/**
 * The request body for a contact: signed summary and sealed card, at a
 * revision above every one seen and above `base` (the revision an edit
 * started from; 0 for a new contact).
 */
async function prepare(session: Session, uid: string, input: ContactDraft, base = 0) {
  const masterKey = toBase64(session.masterKey)
  // Keys of addresses still among the emails, each once, in order, as many as the summary holds.
  const addresses = new Set(input.emails.map((email) => email.address.trim().toLowerCase()))
  const keys = (await withFingerprints(input.keys))
    .filter((key, i, all) => addresses.has(key.address) && all.findIndex((k) => k.address === key.address && k.fingerprint === key.fingerprint) === i)
    .slice(0, MAX_PINNED_KEYS)
  const draft = { ...input, keys }
  const summary = summaryOf(uid, draft)
  const revision = await revisionGuard(session).next(CONTACT_SCOPE, uid, base)
  const signed = await signContactSummary(masterKey, session.envelopeBinding, revision, summary)
  const card = await sealContactCard(masterKey, session.envelopeBinding, uid, revision, toVCard({ ...draft, groups: summary.groups }, uid, summary.name))
  return { body: { summary: signed.summary, signature: signed.signature, card }, revision, uid }
}

/** Another device saved the contact first (the server's `revision_conflict`, or the head saying so). */
export function isRevisionConflict(error: unknown): boolean {
  if (error instanceof ContactChangedError) return true
  return isAxiosError(error) && error.response?.status === 409 && (error.response.data as { code?: string } | undefined)?.code === 'revision_conflict'
}

/**
 * Saves an edit of `existing` made from its revision, with the next head.
 * When another device wrote first: sent again on the new head if the contact
 * is still at that revision (another value changed); refused with
 * {@link ContactChangedError} if the contact itself changed. Stored already (a
 * retry after a lost answer) counts as stored.
 */
export async function putContact(session: Session, existing: Pick<Contact, 'id' | 'uid' | 'revision'>, draft: ContactDraft): Promise<void> {
  const { body, revision } = await prepare(session, existing.uid, draft, existing.revision)
  await listedContacts(session, (index) => {
    const listed = index.revision(existing.uid)
    if (listed === revision) return Promise.resolve(null)
    if (listed !== undefined && listed !== existing.revision) throw new ContactChangedError()
    return Promise.resolve({
      changes: [[existing.uid, revision]] as const,
      send: async (head: string) => {
        await api.put(`/contacts/${existing.id}`, { ...body, baseRevision: existing.revision, head })
      },
    })
  })
  // The revision sealed here, not the server's word for it.
  await revisionGuard(session).accept(CONTACT_SCOPE, existing.uid, revision)
}

/**
 * Adds a contact under `uid`, with the next head; its row id (read back by
 * UID when the head already lists it). The UID is kept for the whole form or
 * dialog that makes the contact, so trying again after an answer that was
 * lost (a network error) finds the contact made, never makes a second.
 */
export async function createContact(session: Session, uid: string, draft: ContactDraft): Promise<string | undefined> {
  const { body, revision } = await prepare(session, uid, draft)
  let id: string | undefined
  const stored = await listedContacts(session, (index) =>
    Promise.resolve(
      // Made already (this form's earlier try): nothing to send.
      index.revision(uid) !== undefined
        ? null
        : {
            changes: [[uid, revision]] as const,
            send: async (head: string) => {
              id = (await api.post<ContactRow>('/contacts', { ...body, head })).data.id
              return true
            },
          },
    ),
  )
  if (stored) {
    // The revision sealed here, not the server's word for it.
    await revisionGuard(session).accept(CONTACT_SCOPE, uid, revision)
    return id
  }
  // Made by an earlier try: its own revision is the one to hold to.
  return (await loadContacts(session)).contacts.find((contact) => contact.uid === uid)?.id
}

/**
 * Applies `edit` to the contact as it is now; when another device saved it
 * meanwhile, reads it again and applies the edit once more.
 */
async function editFresh(
  session: Session,
  read: () => Promise<Contact[]>,
  find: (contacts: Contact[]) => Contact | undefined,
  edit: (contact: Contact) => ContactDraft | null,
): Promise<Contact | undefined> {
  for (let attempt = 0; ; attempt++) {
    const existing = find(await read())
    if (!existing) return undefined
    const draft = edit(existing)
    if (!draft) return existing
    try {
      await putContact(session, existing, draft)
      return existing
    } catch (error) {
      if (attempt > 0 || !isRevisionConflict(error)) throw error
    }
  }
}

function useContactMutation<T, R>(fn: (input: T, session: Session) => Promise<R>) {
  const session = useRequiredSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: T) => fn(input, session),
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

/** Creates a contact, or saves an edit made from its `revision`. */
export function useSaveContact() {
  return useContactMutation(
    async (input: { draft: ContactDraft; existing?: Pick<Contact, 'id' | 'uid' | 'revision'>; uid?: string }, session) => {
      // An edit made on an older revision fails with a revision conflict:
      // the person's form is not laid over another device's change.
      if (input.existing) {
        await putContact(session, input.existing, input.draft)
        return input.existing.id
      }
      return createContact(session, input.uid ?? newUid(), input.draft)
    },
  )
}

/** Deletes contacts, 500 at a time, each batch with the next head (ones already gone are skipped). */
export function useDeleteContacts() {
  return useContactMutation((contacts: Pick<Contact, 'id' | 'uid'>[], session) => deleteContacts(session, contacts))
}

export async function deleteContacts(session: Session, contacts: Pick<Contact, 'id' | 'uid'>[]): Promise<void> {
  for (let i = 0; i < contacts.length; i += 500) {
    const batch = contacts.slice(i, i + 500)
    await listedContacts(session, (index) => {
      const still = batch.filter((contact) => index.revision(contact.uid) !== undefined)
      if (still.length === 0) return Promise.resolve(null)
      return Promise.resolve({
        changes: still.map((contact) => [contact.uid, null] as const),
        send: async (head: string) => {
          await api.post('/contacts/delete', { ids: still.map((contact) => contact.id), head })
        },
      })
    })
  }
}

/**
 * Imports drafts in batches of 500 (each batch all or nothing). Cards keep
 * their own UID unless the address book already has it.
 */
export function useImportContacts() {
  return useContactMutation(
    async (input: { cards: { uid?: string; draft: ContactDraft }[]; takenUids: Set<string> }, session) => {
      let imported = 0
      for (let i = 0; i < input.cards.length; i += 500) {
        const batch = input.cards.slice(i, i + 500)
        const prepared = await Promise.all(
          batch.map(({ uid, draft }) => {
            const ownUid = uid && !input.takenUids.has(uid) && uid.length <= 200 ? uid : newUid()
            input.takenUids.add(ownUid)
            return prepare(session, ownUid, draft)
          }),
        )
        // One head for the batch; a batch whose answer was lost is in the
        // index already at its revisions, and is not sent again.
        await listedContacts(session, (index) =>
          Promise.resolve(
            prepared.every((p) => index.revision(p.uid) === p.revision)
              ? null
              : {
                  changes: prepared.map((p) => [p.uid, p.revision] as const),
                  send: async (head: string) => {
                    await api.post('/contacts/import', { contacts: prepared.map((p) => p.body), head })
                  },
                },
          ),
        )
        const guard = revisionGuard(session)
        await Promise.all(prepared.map((p) => guard.accept(CONTACT_SCOPE, p.uid, p.revision).catch(() => undefined)))
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
 * Trusts `publicKey` (binary, base64) for `address`: on the contact that has
 * the address, or on a new contact named after it (docs/plans/contact-keys.md;
 * a key is trusted only at the person's request). It goes first, used for
 * sending; keys trusted before stay after it, as Proton keeps them.
 */
export function usePinKey() {
  const queryClient = useQueryClient()
  return useContactMutation(
    async (input: { address: string; name?: string; publicKey: string }, session) => {
      const address = input.address.trim().toLowerCase()
      const [described] = await withFingerprints([{ address, publicKey: input.publicKey, fingerprint: '' }])
      if (!described) throw new Error('the key does not read')
      const key: ContactKey = described
      // Fresh, so the key lands on the contact as it is now.
      const read = async () => (await queryClient.fetchQuery({ queryKey: contactsKey, queryFn: () => loadContacts(session), staleTime: 0 })).contacts
      const existing = await editFresh(
        session,
        read,
        (contacts) => contacts.find((c) => c.draft.emails.some((e) => e.address.trim().toLowerCase() === address)),
        (contact) => ({ ...contact.draft, keys: [key, ...contact.draft.keys.filter((k) => !(k.address === address && k.fingerprint === key.fingerprint))] }),
      )
      if (existing) return
      const draft: ContactDraft = { ...emptyDraft(), name: input.name?.trim() ?? '', emails: [{ address }], keys: [key] }
      await createContact(session, newUid(), draft)
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
  return useContactMutation(async (input: { contactId: string; address: string; name?: string }, session) => {
    const address = input.address.trim().toLowerCase()
    const read = async () => (await queryClient.fetchQuery({ queryKey: contactsKey, queryFn: () => loadContacts(session), staleTime: 0 })).contacts
    const existing = await editFresh(
      session,
      read,
      (contacts) => contacts.find((c) => c.id === input.contactId),
      (contact) =>
        contact.draft.emails.some((e) => e.address.trim().toLowerCase() === address)
          ? null
          : {
              ...contact.draft,
              name: contact.draft.name.trim() || contact.draft.givenName || contact.draft.familyName ? contact.draft.name : (input.name?.trim() ?? ''),
              emails: [...contact.draft.emails, { address }],
            },
    )
    if (!existing) throw new Error('this contact no longer exists')
    return existing.id
  })
}

export { useContactEmailSearch, type ContactEmailMatch } from './search'
