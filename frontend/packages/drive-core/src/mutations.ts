import { useMutation, useQueryClient } from '@tanstack/react-query'
import {
  createOwnedCollectionV1,
  generateKey,
  renameFileRecordV1,
  renameOwnedCollectionV1,
  sealNamedShareEnvelope,
  sealPublicLinkCollectionKeyV1,
  toBase64,
} from '@kutup/crypto'
import { sealOwnerLinkKeyV1 } from '@kutup/crypto/publicLink'
import { appUrl } from '@kutup/session/apps'
import api from '@kutup/session/client'
import { peopleKey } from './people'
import { foldersKey } from './folders'
import { useDriveIdentity, type DriveIdentity } from './identity'
import { fileMetadataOf, folderLocation, type DriveFile, type Folder } from './model'
import { rekeyFile } from './rekey'

/** Every Drive mutation refreshes folders (names, timestamps) and the files it touched. */
export function useDriveMutation<T, R = void>(fn: (input: T, me: DriveIdentity) => Promise<R>) {
  const queryClient = useQueryClient()
  const identity = useDriveIdentity()
  return useMutation({
    mutationFn: async (input: T) => {
      if (!identity.data) throw new Error('drive identity is not ready')
      return fn(input, identity.data)
    },
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: foldersKey }),
        queryClient.invalidateQueries({ queryKey: ['files'] }),
        // Files shared with this account by themselves (fileShares.sharedFilesKey).
        queryClient.invalidateQueries({ queryKey: ['shared-files'] }),
        queryClient.invalidateQueries({ queryKey: ['folder-access'] }),
        // A new share is someone to exchange profile keys with.
        queryClient.invalidateQueries({ queryKey: peopleKey }),
      ])
    },
  })
}

export function useCreateFolder() {
  return useDriveMutation(async ({ parent, name }: { parent: Folder; name: string }, me) => {
    const created = await createOwnedCollectionV1(me.masterKey, me.userId, name.trim(), parent.id)
    await api.post('/collections', created.payload)
    return created.payload.id
  })
}

export function useRenameFolder() {
  return useDriveMutation(async ({ folder, name }: { folder: Folder; name: string }, me) => {
    if (!folder.key || !folder.canManage) throw new Error('only the owner can rename a folder')
    // The name envelope binds the owner's id; only owners rename, so it is ours.
    const next = await renameOwnedCollectionV1(
      { id: folder.id, ownerUserId: me.userId, keyEpoch: folder.keyEpoch, nameRevision: folder.nameRevision },
      folder.key,
      name.trim(),
    )
    await api.put(`/collections/${folder.id}`, next)
  })
}

export function useRenameFile() {
  return useDriveMutation(async ({ folder, file: listed, name }: { folder: Folder; file: DriveFile; name: string }) => {
    // A new name is new content: never under a key the folder has left.
    const file = await rekeyFile(folder, listed)
    if (!file.fileKey) throw new Error('file is not open')
    const next = await renameFileRecordV1(
      { id: file.id, keyGeneration: file.keyGeneration, metadataRevision: file.metadataRevision },
      file.fileKey,
      fileMetadataOf(file, { name: name.trim() }),
    )
    await api.put(`/files/${file.id}`, next)
  })
}

export function useSetFolderColor() {
  return useDriveMutation(async ({ folder, color }: { folder: Folder; color: string | null }) => {
    await api.patch(`/collections/${folder.id}/color`, { color })
  })
}

/** Folders go to trash with everything inside them, as one entry. */
export function useTrashFolder() {
  return useDriveMutation(async (folder: Folder) => {
    await api.delete(`/collections/${folder.id}`)
  })
}

export function useTrashFile() {
  return useDriveMutation(async ({ folder, file }: { folder: Folder; file: DriveFile }) => {
    const location = folderLocation(folder)
    await api.delete(
      location.kind === 'local'
        ? `/files/${file.id}`
        : `/drive/federation/shares/${location.shareId}/files/${file.id}`,
    )
  })
}

/** Leave a folder shared from another server (it disappears from Shared with me). */
export function useLeaveRemoteShare() {
  return useDriveMutation(async (folder: Folder) => {
    if (!folder.remoteShareId) throw new Error('not a remote share')
    await api.delete(`/drive/federation/shares/${folder.remoteShareId}`)
  })
}

/** A public link's address: the token for the server, the key in the fragment. */
export function publicLinkUrl(token: string, linkKey: Uint8Array, app: 'drive' | 'photos' = 'drive'): string {
  return appUrl(app, `/s/${token}#key=${encodeURIComponent(toBase64(linkKey))}`)
}

/**
 * A read-only link to a folder's files. The link key never reaches the
 * server in the clear: it is sealed around the folder key there (and, for
 * the owner, under their master key), and travels only in the URL fragment.
 * Every call makes a new link; old ones keep working.
 */
export function useCreatePublicLink(app: 'drive' | 'photos' = 'drive') {
  return useDriveMutation(async (folder: Folder, me) => {
    if (!folder.key) throw new Error('folder is not open')
    const linkKey = await generateKey()
    const id = crypto.randomUUID().toLowerCase()
    const collectionKeyEnvelope = await sealPublicLinkCollectionKeyV1(folder.key, linkKey, {
      collectionId: folder.id,
      ownerUserId: me.userId,
      epoch: folder.keyEpoch,
    })
    // A copy of the link key for the owner: to list and copy the link later,
    // and to keep it working when the folder key rotates.
    const ownerLinkKeyEnvelope = await sealOwnerLinkKeyV1(linkKey, me.masterKey, { linkId: id, ownerUserId: me.userId })
    const { data } = await api.post<{ token: string }>('/share', {
      id,
      shareType: 'collection',
      targetId: folder.id,
      collectionKeyEnvelope,
      ownerLinkKeyEnvelope,
    })
    return publicLinkUrl(data.token, linkKey, app)
  })
}

export interface ShareInput {
  folder: Folder
  recipient: string
  canUpload: boolean
  canDelete: boolean
  uploadQuotaBytes: number | null
  /** People on other servers only view it (an album: they cannot add photos from there). */
  viewOnlyAcrossServers?: boolean
}

export type ShareResult = { kind: 'local'; account: string } | { kind: 'federated'; account: string; inviteUrl: string }

interface LocalRecipient {
  userId: string
  account: string
  driveHpkePublicKey: string
  accountIncarnationId: string
}

interface RemoteRecipient {
  account: string
  driveHpkePublicKey: string
  accountIncarnationId: string
}

/**
 * Share a folder by email (someone on this server) or `user@other-server`
 * (federation). The folder key is sealed to the recipient's Drive key and
 * bound to both accounts; the server checks the binding. Re-sharing with the
 * same person updates their permissions.
 */
export function useShareFolder() {
  return useDriveMutation(async (input: ShareInput, me): Promise<ShareResult> => {
    const { folder } = input
    if (!folder.key) throw new Error('folder is not open')
    const recipient = input.recipient.trim()
    const permissions = {
      canUpload: input.canUpload,
      canDelete: input.canDelete,
      uploadQuotaBytes: input.canUpload ? input.uploadQuotaBytes : null,
    }
    const seal = (publicKey: string, account: string, incarnationId: string) =>
      sealNamedShareEnvelope(folder.key!, me.masterKey, publicKey, {
        collectionId: folder.id,
        epoch: folder.keyEpoch,
        senderAccount: me.account,
        senderIncarnationId: me.incarnationId,
        recipientAccount: account,
        recipientIncarnationId: incarnationId,
      })

    let local: LocalRecipient | null = null
    if (recipient.includes('@')) {
      try {
        local = (await api.get<LocalRecipient>(`/users/by-email/${encodeURIComponent(recipient)}`)).data
      } catch (error) {
        const status = (error as { response?: { status?: number } }).response?.status
        if (status !== 404) throw error
      }
    }
    if (local) {
      const namedShareEnvelope = await seal(local.driveHpkePublicKey, local.account, local.accountIncarnationId)
      await api.post(`/collections/${folder.id}/share`, { recipientUserId: local.userId, namedShareEnvelope, ...permissions })
      return { kind: 'local', account: local.account }
    }

    // Not an account here: `user@server` on another Kutup server.
    const at = recipient.lastIndexOf('@')
    const username = recipient.slice(0, at)
    const server = recipient.slice(at + 1).toLowerCase()
    if (at < 1 || !server.includes('.')) throw new RecipientNotFound()
    const { data: remote } = await api.get<RemoteRecipient>(
      `/drive/federation/users/${encodeURIComponent(username)}`,
      { params: { server } },
    )
    const namedShareEnvelope = await seal(remote.driveHpkePublicKey, remote.account, remote.accountIncarnationId)
    const { data } = await api.post<{ inviteUrl: string }>(`/collections/${folder.id}/federated-shares`, {
      recipientUsername: username,
      recipientServer: server,
      namedShareEnvelope,
      ...(input.viewOnlyAcrossServers ? { canUpload: false, canDelete: false, uploadQuotaBytes: null } : permissions),
    })
    return { kind: 'federated', account: remote.account, inviteUrl: data.inviteUrl }
  })
}

export class RecipientNotFound extends Error {
  constructor() {
    super('no account with that address')
  }
}

const SERVER_NAME = /^(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/
const CAPABILITY = /^[A-Za-z0-9._~-]{32,256}$/

export type InviteKind = 'folder' | 'file' | 'album'

/**
 * Parse a federated invite link (`https://…/invite#server=…&capability=…`,
 * with `&kind=file` for one file, `&kind=album` for a Photos album); null
 * if it is not one.
 */
export function parseInvite(value: string): { server: string; capability: string; kind: InviteKind } | null {
  try {
    const url = new URL(value.trim())
    if (url.pathname.replace(/\/+$/, '') !== '/invite') return null
    const params = new URLSearchParams(url.hash.slice(1))
    const server = params.get('server') ?? ''
    const capability = params.get('capability') ?? ''
    const given = params.get('kind')
    const kind: InviteKind = given === 'file' || given === 'album' ? given : 'folder'
    return SERVER_NAME.test(server) && CAPABILITY.test(capability) ? { server, capability, kind } : null
  } catch {
    return null
  }
}

export function useAcceptInvite() {
  return useDriveMutation(async (invite: { server: string; capability: string; kind: InviteKind }): Promise<{ kind: InviteKind; id: string }> => {
    if (invite.kind === 'file') {
      const { data } = await api.post<{ id: string }>('/drive/federation/file-shares', { server: invite.server, capability: invite.capability })
      return { kind: 'file', id: data.id }
    }
    // Folders and albums share one route; the owner's server says which it is.
    const { data } = await api.post<{ id: string; remoteCollectionId: string; collectionKind: 'folder' | 'album' }>('/drive/federation/shares', {
      server: invite.server,
      capability: invite.capability,
    })
    return { kind: data.collectionKind, id: data.collectionKind === 'album' ? data.remoteCollectionId : data.id }
  })
}

