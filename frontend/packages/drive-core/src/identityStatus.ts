import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useDriveIdentity } from './identity'
import { acceptIdentity, checkIdentity, type ClaimedKeys } from './identityPins'
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
