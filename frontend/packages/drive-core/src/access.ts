import { useQuery, useQueryClient } from '@tanstack/react-query'
import { generateKey, sealNamedShareEnvelope, sealPublicLinkCollectionKeyV1 } from '@kutup/crypto'
import { createCollectionEpochStatement } from '@kutup/crypto/collectionEpoch'
import { sealPreviousCollectionKey } from '@kutup/crypto/collectionKeyring'
import { DRIVE_ENVELOPE_PURPOSE, sealDriveEnvelope } from '@kutup/crypto/driveEnvelope'
import { openOwnerLinkKeyV1 } from '@kutup/crypto/publicLink'
import api from '@kutup/session/client'
import type { DriveIdentity } from './identity'
import { useDriveMutation } from './mutations'
import type { Folder } from './model'

/**
 * Who can open a folder, and taking that access away
 * (docs/plans/drive-share-revocation.md). Removing anyone is a rotation: a
 * new folder key, handed to everyone who stays, applied by the server all
 * at once or not at all.
 */

export interface AccessMember {
  userId: string
  account: string
  accountIncarnationId: string
  drivePublicKey: string
  canUpload: boolean
  canDelete: boolean
  uploadQuotaBytes: number | null
  createdAt: string
}

export interface AccessLink {
  id: string
  token: string
  /** Absent on links made before owners kept a copy: they cannot be kept. */
  ownerLinkKeyEnvelope: string | null
  expiresAt: string | null
  createdAt: string
}

export interface AccessFederated {
  id: string
  recipientUsername: string
  recipientServer: string
  recipientIncarnationId: string
  canUpload: boolean
  canDelete: boolean
  uploadQuotaBytes: number | null
  createdAt: string
}

export interface FolderAccess {
  keyEpoch: number
  epochStatementHash: string
  members: AccessMember[]
  publicLinks: AccessLink[]
  federatedShares: AccessFederated[]
}

export const accessKey = (folderId: string) => ['folder-access', folderId] as const

async function loadAccess(folderId: string): Promise<FolderAccess> {
  return (await api.get<FolderAccess>(`/collections/${folderId}/access`)).data
}

export function useFolderAccess(folder: Folder | undefined) {
  return useQuery({
    queryKey: accessKey(folder?.id ?? ''),
    enabled: Boolean(folder?.canManage && folder.key),
    // Who has access changes from other tabs and devices: never trust a cached list.
    refetchOnMount: 'always',
    queryFn: () => loadAccess(folder!.id),
  })
}

/** A link's key, from the owner's copy. */
export function openLinkKey(link: AccessLink, me: DriveIdentity): Promise<Uint8Array> {
  if (!link.ownerLinkKeyEnvelope) return Promise.reject(new Error('no owner copy of this link'))
  return openOwnerLinkKeyV1(link.ownerLinkKeyEnvelope, me.masterKey, { linkId: link.id, ownerUserId: me.userId })
}

export interface Removal {
  members: string[]
  publicLinks: string[]
  federatedShares: string[]
}

/** The folder's access changed since it was read (or its key did): reload and retry. */
export class AccessChanged extends Error {
  constructor() {
    super('folder access changed')
  }
}

/** A federated recipient's account is no longer the one the folder was shared with. */
export class RecipientChanged extends Error {
  constructor(public readonly account: string) {
    super('recipient identity changed')
  }
}

/**
 * Move `folder` to a new key, keeping everyone in `access` except `removed`.
 * Links made before owners kept a copy of their key cannot be re-wrapped and
 * are always removed.
 */
export async function rotateFolder(
  folder: Folder,
  me: DriveIdentity,
  access: FolderAccess,
  removed: Removal,
  /** More of the request sealed under the new key (an album's photos). */
  sealMore?: (key: Uint8Array, epoch: number) => Promise<Record<string, unknown>>,
): Promise<void> {
  if (!folder.key || !folder.name || !folder.canManage) throw new Error('folder is not open')
  if (access.keyEpoch !== folder.keyEpoch || access.epochStatementHash !== folder.epochStatementHash) {
    throw new AccessChanged()
  }
  const next = folder.keyEpoch + 1
  const key = await generateKey()
  const context = (purpose: (typeof DRIVE_ENVELOPE_PURPOSE)[keyof typeof DRIVE_ENVELOPE_PURPOSE], revision: number) => ({
    purpose,
    epoch: next,
    revision: BigInt(revision),
    objectId: folder.id,
    parentId: me.userId,
  })
  const [epochStatement, ownerKeyEnvelope, previousKeyEnvelope, nameEnvelope] = await Promise.all([
    createCollectionEpochStatement(me.masterKey, key, folder.id, me.userId, next, folder.epochStatementHash),
    sealDriveEnvelope(key, me.masterKey, context(DRIVE_ENVELOPE_PURPOSE.collectionKey, 1)),
    sealPreviousCollectionKey(folder.key, key, folder.id, me.userId, next),
    sealDriveEnvelope(
      new TextEncoder().encode(folder.name),
      key,
      context(DRIVE_ENVELOPE_PURPOSE.collectionName, folder.nameRevision + 1),
    ),
  ])

  const removedLinks = new Set([
    ...removed.publicLinks,
    // A link without an owner copy cannot follow the key: it goes.
    ...access.publicLinks.filter((l) => !l.ownerLinkKeyEnvelope).map((l) => l.id),
  ])
  const seal = (publicKey: string, account: string, incarnationId: string) =>
    sealNamedShareEnvelope(key, me.masterKey, publicKey, {
      collectionId: folder.id,
      epoch: next,
      senderAccount: me.account,
      senderIncarnationId: me.incarnationId,
      recipientAccount: account,
      recipientIncarnationId: incarnationId,
    })

  const members = await Promise.all(
    access.members
      .filter((m) => !removed.members.includes(m.userId))
      .map(async (m) => ({
        userId: m.userId,
        namedShareEnvelope: await seal(m.drivePublicKey, m.account, m.accountIncarnationId),
      })),
  )
  const publicLinks = await Promise.all(
    access.publicLinks
      .filter((l) => !removedLinks.has(l.id))
      .map(async (l) => ({
        id: l.id,
        collectionKeyEnvelope: await sealPublicLinkCollectionKeyV1(key, await openLinkKey(l, me), {
          collectionId: folder.id,
          ownerUserId: me.userId,
          epoch: next,
        }),
      })),
  )
  const federatedShares = await Promise.all(
    access.federatedShares
      .filter((f) => !removed.federatedShares.includes(f.id))
      .map(async (f) => {
        // Their Drive key, through the signed federation lookup; it must still
        // belong to the account incarnation the folder was shared with.
        const { data: remote } = await api.get<{ account: string; driveHpkePublicKey: string; accountIncarnationId: string }>(
          `/drive/federation/users/${encodeURIComponent(f.recipientUsername)}`,
          { params: { server: f.recipientServer } },
        )
        if (remote.accountIncarnationId !== f.recipientIncarnationId) throw new RecipientChanged(remote.account)
        return {
          id: f.id,
          namedShareEnvelope: await seal(remote.driveHpkePublicKey, remote.account, remote.accountIncarnationId),
        }
      }),
  )

  const more = sealMore ? await sealMore(key, next) : {}
  try {
    await api.post(`/collections/${folder.id}/rotate`, {
      ...more,
      fromEpoch: folder.keyEpoch,
      epochStatement,
      ownerKeyEnvelope,
      previousKeyEnvelope,
      nameEnvelope,
      members,
      publicLinks,
      federatedShares,
      removed: {
        members: removed.members,
        publicLinks: [...removedLinks],
        federatedShares: removed.federatedShares,
      },
    })
  } catch (error) {
    if ((error as { response?: { status?: number } }).response?.status === 409) throw new AccessChanged()
    throw error
  }
}

/**
 * Change what someone here may do in a folder (the folder's manager only):
 * add and edit, delete what they added, keeping their upload quota. Their
 * access is sealed again at the folder's current key and the server
 * changes their permissions in place; nobody is removed or re-added, so
 * the folder keeps its key.
 */
export function useSetFolderPermissions() {
  const queryClient = useQueryClient()
  return useDriveMutation(
    async (
      { folder, member, canUpload, canDelete }: { folder: Folder; member: AccessMember; canUpload: boolean; canDelete: boolean },
      me,
    ) => {
      if (!folder.key || !folder.canManage) throw new Error('only the folder\'s manager changes what people may do')
      try {
        const namedShareEnvelope = await sealNamedShareEnvelope(folder.key, me.masterKey, member.drivePublicKey, {
          collectionId: folder.id,
          epoch: folder.keyEpoch,
          senderAccount: me.account,
          senderIncarnationId: me.incarnationId,
          recipientAccount: member.account,
          recipientIncarnationId: member.accountIncarnationId,
        })
        await api.post(`/collections/${folder.id}/share`, {
          recipientUserId: member.userId,
          namedShareEnvelope,
          canUpload,
          canDelete,
          uploadQuotaBytes: canUpload ? member.uploadQuotaBytes : null,
        })
      } finally {
        await queryClient.invalidateQueries({ queryKey: accessKey(folder.id) })
      }
    },
  )
}

/** Remove people or links from a folder (a rotation). */
export function useRemoveAccess() {
  const queryClient = useQueryClient()
  return useDriveMutation(async ({ folder, removed }: { folder: Folder; removed: Removal }, me) => {
    try {
      // Built from access as it is now, not as the list showed it: anyone
      // added since stays (they were not chosen for removal).
      await rotateFolder(folder, me, await loadAccess(folder.id), removed)
    } finally {
      await queryClient.invalidateQueries({ queryKey: accessKey(folder.id) })
    }
  })
}
