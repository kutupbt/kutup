import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect } from 'react'
import { acceptMailForwarding, foldAddress, MAIL_KEY_FLAGS, makeMailForwarding, toBase64, type SealedMailKey } from '@kutup/crypto'
import api from '@kutup/session/client'
import { useRequiredSession, type Session } from '@kutup/session/store'
import { mailKey, useMailAccount, type MailAccount } from './api'
import type { FilterCondition } from './filters'
import { AddressDisabled, addressKeys, GroupAddress, NoKutupAddress, type AddressKeys } from './keys'
import { checkedAddresses, encryptionOff, encryptionOffList, KeyListNotSigned, settleOwedKeyLists, type AddressRow, type CheckedAddress } from './keyList'

// Mail forwarding (docs/plans/mail-forwarding.md), as Proton's: to a Kutup
// address on this server it is end to end (the server re-encrypts each key
// packet for the forwardee with a proxy factor and reads nothing); to any
// other address it is outside, and the address's end-to-end encryption is
// off while any outside forwarding lasts. The conditions are the filters'
// without the recipient, readable to the server as filters are.

export type ForwardingKind = 'end_to_end' | 'outside'
export type ForwardingState = 'pending' | 'active' | 'outdated' | 'paused' | 'rejected'
/** A forwarding's conditions: the filter conditions on sender, subject and attachments. */
export type ForwardingCondition = FilterCondition & { field: 'sender' | 'subject' | 'attachments' }

export interface MailForwarding {
  id: string
  kind: ForwardingKind
  state: ForwardingState
  forwarderAddress: string
  forwardeeEmail: string
  match: 'all' | 'any'
  conditions: ForwardingCondition[]
  /** Messages that couldn't be forwarded (end-to-end mail sent outside, …). */
  skipped: number
  /** Why an outside forwarding stopped on its own: paused after bounces, or today's budget spent. */
  notice: 'bounces' | 'budget' | null
  createdAt: string
  expiresAt: string | null
}

export interface MailForwardings {
  /** "From me": the account's addresses' forwardings. */
  outgoing: MailForwarding[]
  /** "To me": forwardings to the account's addresses. */
  incoming: MailForwarding[]
}

/**
 * Post-quantum mail isn't built yet (docs/plans/mail-forwarding.md, "The
 * post-quantum hook"). Once it is, an address with an end-to-end forwarding
 * stays on classic encryption while it lasts, and the forwarding dialog's
 * confirmation, the address's label and the note when the last such
 * forwarding ends say so; until then that copy isn't in the build.
 */
export const POST_QUANTUM_MAIL = false

/** How long a forwardee has to accept (the server's 7 days). */
export const FORWARDING_ACCEPT_MS = 7 * 24 * 60 * 60 * 1000

export const forwardingsKey = ['mail', 'forwardings'] as const
const addressesKey = ['mail', 'own-addresses'] as const

/** The account's forwardings, both ways. */
export function useForwardings() {
  return useQuery({
    queryKey: forwardingsKey,
    queryFn: async () => (await api.get<MailForwardings>('/mail/forwardings')).data,
  })
}

/**
 * The account's addresses as key lists need them. Any whose last outside
 * forwarding ended without this client get their end-to-end encryption back
 * first (`keyListOwed`).
 */
export function useOwnAddresses() {
  const session = useRequiredSession()
  return useQuery({
    queryKey: addressesKey,
    queryFn: async () => {
      let { data } = await api.get<AddressRow[]>('/mail/addresses')
      if (await settleOwedKeyLists(session, data)) data = (await api.get<AddressRow[]>('/mail/addresses')).data
      return checkedAddresses(session, data)
    },
  })
}

/**
 * Turns end-to-end encryption back on, once a session, for an address whose
 * last outside forwarding ended without this client (declined, or deleted
 * by the forwardee): `GET /api/mail/addresses` says `keyListOwed`.
 */
export function useSettleOwedKeyLists() {
  const session = useRequiredSession()
  const queryClient = useQueryClient()
  useEffect(() => {
    let live = true
    void (async () => {
      try {
        const { data } = await api.get<AddressRow[]>('/mail/addresses')
        if ((await settleOwedKeyLists(session, data)) && live) {
          void queryClient.invalidateQueries({ queryKey: [...mailKey, 'account'] })
          void queryClient.invalidateQueries({ queryKey: addressesKey })
        }
      } catch (error) {
        // Tried again next session; the server keeps saying it's owed.
        console.warn('mail: could not turn end-to-end encryption back on', error)
      }
    })()
    return () => {
      live = false
    }
  }, [session, queryClient])
}

/** The forwardee address can't be forwarded to (or isn't what the user confirmed). */
export class ForwardeeRefused extends Error {
  constructor(readonly reason: 'ownAddress' | 'group' | 'unverified' | 'unknown' | 'kindChanged' | 'disabled') {
    super(`this address can't be forwarded to (${reason})`)
  }
}

/**
 * Which kind a forwarding to `email` is: end to end to a person's Kutup
 * address on this server (with their verified keys), outside for anything
 * else (another Kutup server included). Shared mailboxes and the account's
 * own addresses are refused, as Proton refuses catch-alls. An address on
 * this server's domain without a Kutup key is refused too, never taken as
 * outside: the server's "no such address" can't turn a Kutup address into
 * one whose forwarding turns end-to-end encryption off.
 */
export async function forwardingKindOf(
  account: Pick<MailAccount, 'serverDomain' | 'isOwnAddress' | 'groupHolder'>,
  email: string,
): Promise<{ kind: 'end_to_end'; keys: AddressKeys } | { kind: 'outside' }> {
  if (account.isOwnAddress(email)) throw new ForwardeeRefused('ownAddress')
  let keys: AddressKeys
  try {
    keys = await addressKeys(email)
  } catch (error) {
    if (error instanceof NoKutupAddress) {
      if (domainOf(email) === account.serverDomain) throw new ForwardeeRefused('unknown')
      return { kind: 'outside' }
    }
    if (error instanceof GroupAddress) throw new ForwardeeRefused('group')
    if (error instanceof AddressDisabled) throw new ForwardeeRefused('disabled')
    throw new ForwardeeRefused('unverified')
  }
  if (keys.group) throw new ForwardeeRefused('group')
  // A person on this server: their account names this server, as the
  // account's own does (`/user/me`).
  if (keys.accountRef?.server !== account.groupHolder.account.server) return { kind: 'outside' }
  return { kind: 'end_to_end', keys }
}

function domainOf(email: string): string {
  return email.slice(email.lastIndexOf('@') + 1).trim().toLowerCase()
}

/** Whether two addresses are one (as Kutup folds them). */
async function sameAddress(a: string, b: string): Promise<boolean> {
  const [x, y] = await Promise.all([foldAddress(a), foldAddress(b)])
  return x !== null && x === y
}

export interface NewForwarding {
  /** The forwarder address (one of the account's). */
  from: CheckedAddress
  to: string
  /** The kind the user confirmed: a forwarding of another kind now is refused. */
  kind: ForwardingKind
  match: 'all' | 'any'
  conditions: ForwardingCondition[]
}

/** The address's primary key, as the key list this account signed names it, sealed. */
function sealedPrimary(session: Pick<Session, 'masterKey' | 'envelopeBinding'>, address: CheckedAddress): SealedMailKey {
  if (!address.verifiedList) throw new KeyListNotSigned()
  // Usable, as Mail's own primary must be: neither compromised nor obsolete.
  const usable = MAIL_KEY_FLAGS.notCompromised | MAIL_KEY_FLAGS.notObsolete
  const entry = address.verifiedList.keys.find((key) => key.primary && (key.flags & usable) === usable)
  // Its public key checked against the signed fingerprints (`listed`).
  const primary = entry && address.keys.find((key) => !key.forwarding && key.listed && key.fingerprint === entry.fingerprint)
  if (!primary) throw new Error(`${address.address} has no primary key`)
  return {
    masterKeyBase64: toBase64(session.masterKey),
    binding: session.envelopeBinding,
    address: address.address,
    envelope: primary.privateKeyEnvelope,
    fingerprint: primary.fingerprint,
  }
}

/**
 * Sets a forwarding up: end to end, the material made here from the
 * forwarder's primary key and sealed to the forwardee's (from their verified
 * key list); outside, with the next key list turning the address's end-to-end
 * encryption off when no outside forwarding has yet.
 */
export function useCreateForwarding() {
  const session = useRequiredSession()
  const account = useMailAccount()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (input: NewForwarding) => {
      if (!account.data) throw new Error('the mail account is not loaded')
      const id = crypto.randomUUID()
      const body: Record<string, unknown> = {
        id,
        forwarderAddressId: input.from.id,
        forwardeeEmail: input.to,
        match: input.match,
        conditions: input.conditions,
      }
      const kind = await forwardingKindOf(account.data, input.to)
      if (kind.kind !== input.kind) throw new ForwardeeRefused('kindChanged')
      if (kind.kind === 'end_to_end') {
        const now = new Date()
        body.endToEnd = await makeMailForwarding(
          sealedPrimary(session, input.from),
          { address: kind.keys.address, publicKey: kind.keys.primary },
          id,
          now,
          new Date(now.getTime() + FORWARDING_ACCEPT_MS),
        )
        body.forwardeeEmail = kind.keys.address
      } else if (!encryptionOff(input.from)) {
        const list = await encryptionOffList(session, input.from)
        body.keyList = { data: list.data, signature: list.signature }
      }
      return (await api.post<MailForwarding>('/mail/forwardings', body)).data
    },
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: forwardingsKey })
      void queryClient.invalidateQueries({ queryKey: addressesKey })
      // The address's keys and flags changed for Mail too.
      void queryClient.invalidateQueries({ queryKey: [...mailKey, 'account'] })
    },
  })
}

/**
 * Re-enables an outdated or declined end-to-end forwarding: new material
 * from the forwarder's current primary key (Proton's re-enable).
 */
export function useRenewForwarding() {
  const session = useRequiredSession()
  const account = useMailAccount()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (input: { forwarding: MailForwarding; from: CheckedAddress }) => {
      if (!account.data) throw new Error('the mail account is not loaded')
      if (input.forwarding.kind !== 'end_to_end' || !(await sameAddress(input.from.address, input.forwarding.forwarderAddress))) {
        throw new Error('the forwarding is not an end-to-end one from this address')
      }
      // Still a person's Kutup address on this server, as when it was set up.
      const kind = await forwardingKindOf(account.data, input.forwarding.forwardeeEmail)
      if (kind.kind !== 'end_to_end') throw new ForwardeeRefused('kindChanged')
      const keys = kind.keys
      if (!(await sameAddress(keys.address, input.forwarding.forwardeeEmail))) throw new ForwardeeRefused('kindChanged')
      const now = new Date()
      const endToEnd = await makeMailForwarding(
        sealedPrimary(session, input.from),
        { address: keys.address, publicKey: keys.primary },
        input.forwarding.id,
        now,
        new Date(now.getTime() + FORWARDING_ACCEPT_MS),
      )
      await api.put(`/mail/forwardings/${input.forwarding.id}`, { endToEnd })
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: forwardingsKey }),
  })
}

/**
 * Accepts an end-to-end forwarding to one of the account's addresses: the
 * activation is opened with that address's key and checked against the
 * forwarder's verified key list (never the server's word), then the
 * forwarding key is kept like the address's other keys.
 */
export function useAcceptForwarding() {
  const session = useRequiredSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (input: { forwarding: MailForwarding; to: CheckedAddress }) => {
      const { data: pending } = await api.get<{
        forwardingId: string
        forwarderAddress: string
        forwardeeAddress: string
        activation: string
        expiresAt: string
      }>(`/mail/forwardings/${input.forwarding.id}/activation`)
      // The activation binds the forwarder's address (checked when it's
      // opened); it must be the one this account was shown and accepts.
      const ours =
        pending.forwardingId === input.forwarding.id &&
        (await sameAddress(pending.forwardeeAddress, input.to.address)) &&
        (await sameAddress(pending.forwarderAddress, input.forwarding.forwarderAddress))
      if (!ours) throw new Error('the activation is for another forwarding')
      const forwarder = await addressKeys(pending.forwarderAddress)
      if (!(await sameAddress(forwarder.address, input.forwarding.forwarderAddress))) {
        throw new Error('the activation is for another forwarding')
      }
      const key = await acceptMailForwarding(
        sealedPrimary(session, input.to),
        { address: forwarder.address, publicKey: forwarder.primary },
        pending.forwardingId,
        pending.activation,
      )
      await api.post(`/mail/forwardings/${input.forwarding.id}/accept`, {
        publicKey: key.publicKey,
        privateKeyEnvelope: key.privateKeyEnvelope,
      })
    },
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: forwardingsKey })
      void queryClient.invalidateQueries({ queryKey: addressesKey })
      // The new forwarding key opens forwarded mail.
      void queryClient.invalidateQueries({ queryKey: [...mailKey, 'account'] })
    },
  })
}

type Action = 'pause' | 'resume' | 'decline' | 'delete' | 'reinvite'

/** The simple actions on a forwarding, by its state (docs/plans/mail-forwarding.md, "States and actions"). */
export function useForwardingAction() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ id, action }: { id: string; action: Action }) => {
      if (action === 'delete') await api.delete(`/mail/forwardings/${id}`)
      else if (action === 'decline') await api.post(`/mail/forwardings/${id}/decline`)
      else await api.put(`/mail/forwardings/${id}/${action}`)
    },
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: forwardingsKey })
      // Ending the last outside forwarding owes a key list.
      void queryClient.invalidateQueries({ queryKey: addressesKey })
    },
  })
}

/** Changes which mail a forwarding sends on. */
export function useForwardingConditions() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ id, match, conditions }: { id: string; match: 'all' | 'any'; conditions: ForwardingCondition[] }) => {
      await api.put(`/mail/forwardings/${id}/conditions`, { match, conditions })
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: forwardingsKey }),
  })
}

/** What a forwarder may do with a forwarding of theirs in each state (Proton's table). */
export function forwarderActions(forwarding: MailForwarding): ('edit' | 'pause' | 'resume' | 'reinvite' | 'renew' | 'delete')[] {
  const outside = forwarding.kind === 'outside'
  switch (forwarding.state) {
    case 'pending':
      return outside ? ['edit', 'reinvite', 'delete'] : ['edit', 'delete']
    case 'active':
      return ['edit', 'pause', 'delete']
    case 'paused':
      return ['resume', 'delete']
    case 'outdated':
      return ['renew', 'delete']
    case 'rejected':
      return outside ? ['reinvite', 'delete'] : ['renew', 'delete']
  }
}

/** What a forwardee may do with a forwarding to them in each state. */
export function forwardeeActions(forwarding: MailForwarding): ('accept' | 'decline' | 'delete')[] {
  return forwarding.state === 'pending' ? ['accept', 'decline'] : ['delete']
}
