import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useRef } from 'react'
import { deriveAccountIdentityKeys, toBase64, verifyMailKeyList, type SignedMailKeyList } from '@kutup/crypto'
import { addFirstAddressKey } from '@kutup/mail-core/addressKey'
import api from '@kutup/session/client'
import { useRequiredSession } from '@kutup/session/store'

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
