import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useDriveIdentity } from './identity'
import { acceptIdentity, checkIdentity, IdentityUnproven, isPinned, personSafetyNumber, verifyPerson, type ClaimedKeys } from './identityPins'
import type { Folder } from './model'

const statusKey = ['identity-status'] as const

/**
 * Whether `account`'s `claimed` keys are theirs (docs/plans/drive-identity-pins.md).
 * Checked once a page and kept: a person's identity does not change while
 * one is looked at.
 */
export function useIdentityStatus(account: string | null | undefined, claimed: ClaimedKeys = {}) {
  const identity = useDriveIdentity()
  return useQuery({
    queryKey: [
      ...statusKey,
      account ?? '',
      claimed.driveHpkePublicKey ?? '',
      claimed.driveSigningPublicKey ?? '',
      claimed.incarnationId ?? '',
      claimed.authorityPublicKey ?? '',
    ],
    enabled: Boolean(account && identity.data),
    staleTime: Infinity,
    queryFn: () => checkIdentity(identity.data!, account!, claimed),
  })
}

/**
 * Whether an address is a Kutup account worth a shield: one on this server,
 * or one in the list of people met before. Others (an ordinary email
 * address) are never looked up, so no other server learns who is asked about.
 */
export function useIsKutupAccount(address: string | null | undefined) {
  const identity = useDriveIdentity()
  const account = address?.trim().toLowerCase() ?? ''
  const local = Boolean(identity.data && account.endsWith(`@${identity.data.account.split('@')[1]}`))
  const listed = useQuery({
    queryKey: [...statusKey, 'listed', account],
    enabled: Boolean(account && identity.data && !local),
    staleTime: Infinity,
    queryFn: () => isPinned(identity.data!, account),
  })
  return Boolean(account) && (local || listed.data === true)
}

/** Trust `account`'s new identity from now on (after a reset the user knows about). */
export function useAcceptIdentity() {
  const identity = useDriveIdentity()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (account: string) => {
      if (!identity.data) throw new Error('not signed in')
      await acceptIdentity(identity.data, account)
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: statusKey }),
  })
}

/** The keys someone else's folder was shared with, to check against its owner. */
export function folderOwnerClaim(folder: Pick<Folder, 'ownerSigningPublicKey' | 'ownerIncarnationId' | 'ownerAuthorityPublicKey'>): ClaimedKeys {
  return {
    driveSigningPublicKey: folder.ownerSigningPublicKey || undefined,
    incarnationId: folder.ownerIncarnationId || undefined,
    authorityPublicKey: folder.ownerAuthorityPublicKey || undefined,
  }
}

/** The safety number to compare with `account` in person. */
export function usePersonSafetyNumber(account: string | null, enabled = true) {
  const identity = useDriveIdentity()
  return useQuery({
    queryKey: ['safety-number', account ?? ''],
    enabled: Boolean(enabled && account && identity.data),
    staleTime: Infinity,
    // A passing failure (the lookup limit, the network) is tried again; an
    // account without a binding is not.
    retry: (failures, error) => !(error instanceof IdentityUnproven) && failures < 2,
    queryFn: () => personSafetyNumber(identity.data!, account!),
  })
}

/** Verify `account` with the safety QR scanned from their device. */
export function useVerifyPerson() {
  const identity = useDriveIdentity()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ account, scanned }: { account: string; scanned: string }) => {
      if (!identity.data) throw new Error('not signed in')
      await verifyPerson(identity.data, account, scanned)
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: statusKey }),
  })
}
