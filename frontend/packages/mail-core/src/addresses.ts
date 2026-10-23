// The account's addresses as Proton's "Identity and addresses" manages them
// (docs/api.md, "PUT /api/mail/addresses/order" and after): their order,
// whose first enabled address is the default, adding one on a verified
// custom domain, generating its missing keys, and disabling, enabling and
// deleting one. Disabling and enabling publish the address's next signed key
// list, made and signed here (Rust/WASM), as every key list is.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import api from '@kutup/session/client'
import { useRequiredSession, type Session } from '@kutup/session/store'
import type { OwnAddressRow } from './api'
import { addFirstAddressKey } from './addressKey'
import { domainUsable, type MailDomains } from './domains'
import { checkedAddresses, disabledKeyList, enabledKeyList } from './keyList'

export type AddressStatus = 'default' | 'active' | 'disabled' | 'missingKeys'

/** Proton's address statuses (`getStatus`): the default first, then the rest. */
export function addressStatuses(row: OwnAddressRow, isDefault: boolean): AddressStatus[] {
  const statuses: AddressStatus[] = []
  if (isDefault) statuses.push('default')
  statuses.push(row.disabled ? 'disabled' : 'active')
  if (row.keys.length === 0 && row.keyList === null) statuses.push('missingKeys')
  return statuses
}

/** The account's current addresses, in its order (the old ones after a rename left out). */
export function useOwnAddresses() {
  return useQuery({
    queryKey: ['mail', 'addresses'],
    queryFn: async () => (await api.get<OwnAddressRow[]>('/mail/addresses')).data.filter((row) => row.state === 'active'),
  })
}

/** The default: the first enabled address with a key (or the first enabled one). */
export function defaultAddressId(rows: OwnAddressRow[]): string | undefined {
  const chosen = rows.find((row) => row.isDefault)
  if (chosen) return chosen.id
  // None usable yet: the one that gets its first key.
  const enabled = rows.filter((row) => !row.disabled)
  return (enabled.find((row) => row.keys.length > 0 || row.keyList !== null) ?? enabled[0])?.id
}

/** A custom domain an address can be added on: verified (or warned), as the server allows. */
export interface UsableDomain {
  id: string
  name: string
}

export function useAddressDomains() {
  return useQuery({
    queryKey: ['mail', 'domains', 'usable'],
    // No Mail domains on this server (404): none to add on.
    queryFn: async (): Promise<UsableDomain[]> => {
      const response = await api.get<MailDomains>('/mail/domains').catch(() => null)
      return (response?.data.domains ?? []).filter(domainUsable).map(({ id, name }) => ({ id, name }))
    },
  })
}

async function checkedRow(session: Session, row: OwnAddressRow) {
  const [checked] = await checkedAddresses(session, [row])
  return checked
}

function useAddressMutation<T>(run: (session: Session, input: T) => Promise<unknown>) {
  const session = useRequiredSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: T) => run(session, input),
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: ['mail', 'addresses'] })
      // The composer's From and the default address come from the account.
      void queryClient.invalidateQueries({ queryKey: ['mail', 'account'] })
    },
  })
}

/** Moves the addresses into `ids`' order ("Set as default" moves one first). */
export function useOrderAddresses() {
  return useAddressMutation(async (_session, ids: string[]) => api.put('/mail/addresses/order', { ids }))
}

export async function disableAddress(session: Session, row: OwnAddressRow) {
  const list = await disabledKeyList(session, await checkedRow(session, row))
  await api.put(`/mail/addresses/${row.id}/disable`, { keyList: { data: list.data, signature: list.signature } })
}

export function useDisableAddress() {
  return useAddressMutation(disableAddress)
}

export function useEnableAddress() {
  return useAddressMutation(async (session, row: OwnAddressRow) => {
    const list = await enabledKeyList(session, await checkedRow(session, row))
    await api.put(`/mail/addresses/${row.id}/enable`, { keyList: { data: list.data, signature: list.signature } })
  })
}

/**
 * Deletes an address on a custom domain, disabling it first as Proton's
 * client does; one that never had a key (nothing to disable) at once.
 */
export function useDeleteAddress() {
  return useAddressMutation(async (session, row: OwnAddressRow) => {
    const keyless = row.keys.length === 0 && row.keyList === null
    if (!row.disabled && !keyless) await disableAddress(session, row)
    await api.put(`/mail/addresses/${row.id}/delete`)
  })
}

/** A new address on a custom domain, with its first key made here. */
export function useAddAddress() {
  return useAddressMutation(async (session, input: { local: string; domainId: string }) => {
    const { data } = await api.post<{ id: string; address: string }>('/mail/domains/addresses', input)
    await addFirstAddressKey(session, data)
    return data
  })
}

/** Proton's "Generate missing keys": a first key for addresses that have none. */
export function useGenerateMissingKeys() {
  return useAddressMutation(async (session, rows: OwnAddressRow[]) => {
    for (const row of rows) await addFirstAddressKey(session, row)
  })
}
