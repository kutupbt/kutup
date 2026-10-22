// Custom mail domains (docs/plans/mail-custom-domains.md), Proton's shape:
// a domain the account proves it owns (a TXT record), the records to publish
// for it with the state of each as the server last checked them ("Refresh
// status" checks now), its catch-all, and removing it. Addresses on it are
// made and managed in Identity and addresses (./addresses).

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import api from '@kutup/session/client'

/** One record the owner publishes. */
export interface DnsRecord {
  type: 'TXT' | 'MX' | 'CNAME'
  /** Relative to the domain: `@`, `_dmarc`, `kutup1._domainkey`. */
  host: string
  value: string
  priority?: number
}

/** Proton's `DOMAIN_STATE`. */
export const DOMAIN_STATE = { default: 0, verified: 1, warn: 2 } as const
/** Proton's `VERIFY_STATE`. */
export const VERIFY_STATE = { default: 0, exist: 1, good: 2 } as const
/** Proton's `MX_STATE`. */
export const MX_STATE = { default: 0, noUs: 1, incUs: 2, good: 3, backup: 4 } as const
/** Proton's `SPF_STATE`. */
export const SPF_STATE = { default: 0, one: 1, mult: 2, good: 3 } as const
/** Proton's `DKIM_STATE`. */
export const DKIM_STATE = { default: 0, error: 3, good: 4, delegated: 5, warning: 6 } as const
/** Proton's `DMARC_STATE`. */
export const DMARC_STATE = { default: 0, one: 1, mult: 2, good: 3, relaxed: 4 } as const

export interface MailDomain {
  id: string
  name: string
  state: number
  verifyState: number
  mxState: number
  spfState: number
  dkimState: number
  dmarcState: number
  /** Verified, waiting for an administrator (the `approve` mode). */
  awaitingApproval: boolean
  /** Sending and delivery stopped: its TXT and MX are both gone. */
  stopped: boolean
  catchAllAddressId: string | null
  addressCount: number
  records: { verify: DnsRecord; mx: DnsRecord[]; spf: DnsRecord; dkim: DnsRecord[]; dmarc: DnsRecord }
  createdAt: string
  checkedAt: string | null
  /** When a domain in `warn` stops, unless its record returns. */
  warnedAt: string | null
}

export interface MailDomains {
  domains: MailDomain[]
  used: number
  max: number
  mode: 'everyone' | 'approve' | 'off'
}

export const domainsKey = ['mail', 'domains'] as const

/** The account's domains, or `null` where the server has no Mail domains (404). */
export function useDomains() {
  return useQuery({
    queryKey: domainsKey,
    queryFn: async (): Promise<MailDomains | null> => {
      try {
        return (await api.get<MailDomains>('/mail/domains')).data
      } catch (error) {
        if ((error as { response?: { status?: number } }).response?.status === 404) return null
        throw error
      }
    },
  })
}

function useDomainMutation<T, R>(run: (input: T) => Promise<R>) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: run,
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: domainsKey })
      // Addresses on a domain, and the composer's From, follow it.
      void queryClient.invalidateQueries({ queryKey: ['mail', 'addresses'] })
      void queryClient.invalidateQueries({ queryKey: ['mail', 'account'] })
    },
  })
}

/** Adds a domain: pending until its TXT record proves it. */
export function useAddDomain() {
  return useDomainMutation(async (name: string) => (await api.post<MailDomain>('/mail/domains', { name })).data)
}

/** Checks a domain's DNS now (Proton's "Refresh status" and "Verify"). */
export function useRefreshDomain() {
  return useDomainMutation(async (id: string) => (await api.get<MailDomain>(`/mail/domains/${id}`, { params: { refresh: 1 } })).data)
}

/** Sets the domain's catch-all address, or none. */
export function useCatchAll() {
  return useDomainMutation(async ({ id, addressId }: { id: string; addressId: string | null }) => {
    await api.put(`/mail/domains/${id}/catch-all`, { addressId })
  })
}

/** Removes a domain: its addresses stop receiving and sending. */
export function useDeleteDomain() {
  return useDomainMutation(async (id: string) => {
    await api.delete(`/mail/domains/${id}`)
  })
}

/** Whether addresses can be made on it (Proton's `getIsDomainActive`). */
export function domainUsable(domain: MailDomain): boolean {
  return (domain.state === DOMAIN_STATE.verified || domain.state === DOMAIN_STATE.warn) && !domain.stopped && !domain.awaitingApproval
}
