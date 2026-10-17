import { useQuery } from '@tanstack/react-query'
import { parseAccount } from '@kutup/chat-core/identity'
import { useContactLookup } from '@kutup/contacts-core/api'
import type { Contact } from '@kutup/contacts-core/model'
import { holdsAddress } from '@kutup/drive-core/identityPins'
import { driveIdentity } from '../../state/accountNames'

/**
 * The address book card for the account `peer` shown at `address`. Cards
 * are kept by address, so a card is this account's only when the pin list
 * says it holds the address (`holdsAddress`): someone who took a name
 * another person left never gets that person's card, its name or its link.
 * `card` is undefined when there is none for them; `ready` once both the
 * address book and the check have answered.
 */
export function useContactFor(peer: string, address: string): { ready: boolean; card: Contact | undefined; taken: boolean } {
  const contacts = useContactLookup()
  const saved = contacts.ready ? contacts.find(address) : undefined
  const holder = useQuery({
    queryKey: ['chat-contact-holder', peer, address.toLowerCase()],
    enabled: Boolean(saved),
    staleTime: 60_000,
    queryFn: async () => {
      const account = parseAccount(peer)
      const me = driveIdentity()
      return Boolean(account && me && (await holdsAddress(await me, account, address)))
    },
  })
  if (!contacts.ready) return { ready: false, card: undefined, taken: false }
  if (!saved) return { ready: true, card: undefined, taken: false }
  if (holder.isPending) return { ready: false, card: undefined, taken: false }
  // A card for the address that is someone else's: neither theirs nor offered again.
  return holder.data ? { ready: true, card: saved, taken: false } : { ready: true, card: undefined, taken: true }
}
