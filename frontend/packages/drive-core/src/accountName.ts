import { useQuery } from '@tanstack/react-query'
import { sameAccount, type AccountRef } from '@kutup/crypto/accountRef'
import api from '@kutup/session/client'
import { useDriveIdentity, type DriveIdentity } from './identity'
import { pinnedNameOf } from './identityPins'

// What to call an account that a record names by its permanent id
// (docs/plans/account-ids.md): a place's "added by", a comment's author. As
// Signal shows an account's own name, never one typed for it:
// - this account: its own address;
// - an account the pin list knows: the address its own signed rename chain
//   proves (or the one it was first met at);
// - anyone else: the address their server says the account has now (the
//   handle Signal shows for a username lookup), looked up once a page.

const byId = new Map<string, Promise<string | null>>()

/**
 * The address an account's server says it has now (a label, never who it
 * is); null when it cannot say. Asked once a page unless `fresh`.
 */
export function serverAddressOf(account: AccountRef, fresh = false): Promise<string | null> {
  const key = `${account.accountId}@${account.server}`
  if (fresh) byId.delete(key)
  let pending = byId.get(key)
  if (!pending) {
    pending = api
      .get<{ server: string; accountId: string; account: string }>(`/users/by-id/${encodeURIComponent(account.accountId)}`, {
        params: { server: account.server },
      })
      // The answer must be for the account asked about, an address on its server.
      .then(({ data }) =>
        sameAccount(data, account) && data.account.endsWith(`@${account.server}`) ? data.account : null,
      )
      .catch(() => {
        byId.delete(key)
        return null
      })
    byId.set(key, pending)
  }
  return pending
}

/** The address to show for `account`, or null when nobody can say. */
export async function nameOfAccount(me: DriveIdentity, account: AccountRef): Promise<string | null> {
  if (sameAccount(account, me.accountRef)) return me.account
  return (await pinnedNameOf(me, account).catch(() => null)) ?? serverAddressOf(account)
}

/** The address to show for `account` (null while unknown). */
export function useAccountName(account: AccountRef | null) {
  const identity = useDriveIdentity()
  return useQuery({
    queryKey: ['account-name', account?.server ?? '', account?.accountId ?? '', identity.data?.account],
    enabled: Boolean(account && identity.data),
    staleTime: 5 * 60_000,
    queryFn: () => nameOfAccount(identity.data!, account!),
  })
}

/** Test seam: forget what this page looked up. */
export function resetAccountNamesForTesting(): void {
  byId.clear()
}
