import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect } from 'react'
import { isAxiosError } from 'axios'
import { generateKey, openFileMetadataV1, openFileShareEnvelope, rekeyFileRecordV1, sealFileShareEnvelope, sealPublicLinkFileKeyV1 } from '@kutup/crypto'
import { openOwnerLinkKeyV1, sealOwnerLinkKeyV1 } from '@kutup/crypto/publicLink'
import api from '@kutup/session/client'
import { useDriveIdentity, type DriveIdentity } from './identity'
import { AccessChanged, RecipientChanged } from './access'
import { loadFolderFiles, toDriveFile, type FileRowLike } from './files'
import { useFolders } from './folders'
import { opensInOffice } from './editorKind'
import { publicLinkUrl, useDriveMutation, RecipientNotFound } from './mutations'
import { rekeyFile } from './rekey'
import { fileMetadataOf, type DriveFile, type Folder } from './model'

/**
 * Sharing a single file (docs/plans/drive-file-sharing.md), like Proton
 * Drive and CryptPad: the owner seals the file's own key to someone here.
 * They open the file, its versions and its live edits with it, never the
 * folder. Removing someone moves the file to a new key.
 */

// ---------------------------------------------------------------- recipient

interface SharedFileRow {
  file: FileRowLike
  shareEnvelope: string
  canEdit: boolean
  keyGeneration: number
  folderKeyCurrent: boolean
  ownerUserId: string
  ownerAccount: string
  ownerIncarnationId: string
  ownerSigningPublicKey: string
  /** Who sealed the envelope: the owner, or an editor the owner lets share. */
  sharerAccount: string
  sharerIncarnationId: string
  sharerSigningPublicKey: string
  editorsCanShare: boolean
  sharedAt: string
  /** Behind: the metadata of the share's generation, sealed under the key it opens. */
  metadataAtShare?: { envelope: string; revision: number }
}

/**
 * - `ready`: open, and editable if shared for editing.
 * - `editsWait`: open, but read-only until the owner's app moves the file
 *   to its folder's current key (someone left the folder).
 * - `waiting`: someone else moved the file to a new key; the owner's app has
 *   not handed it on yet. Nothing current can be opened.
 * - `gone`: a file from another server that is no longer shared (or its
 *   server cannot be reached); it can only be removed from the list.
 */
export type SharedFileState = 'ready' | 'editsWait' | 'waiting' | 'gone'

export interface SharedFile {
  file: DriveFile
  /** Where the file lives, as far as the recipient can tell: no key, no name. */
  container: Folder
  canEdit: boolean
  /** An editor the owner lets share it on (adding people, not removing). */
  canShare: boolean
  state: SharedFileState
  ownerAccount: string
  sharedAt: string
  /** From another server: the accepted invite's id here (to remove it). */
  remoteShareId?: string
}

export const sharedFilesKey = ['shared-files'] as const

type Opened = { fileKey: Uint8Array; metadata: { name: string; mimeType: string; size: number } } | null

const opened = new Map<string, Promise<Opened>>()

async function openShared(row: SharedFileRow, me: DriveIdentity, remoteShareId?: string): Promise<SharedFile> {
  const { file } = row
  const current = row.keyGeneration === file.keyGeneration
  let result: Opened = null
  const behind = row.metadataAtShare
  if (current || behind) {
    const cacheKey = `${file.id}:${row.shareEnvelope}:${current ? file.metadataEnvelope : behind!.envelope}`
    let pending = opened.get(cacheKey)
    if (!pending) {
      pending = (async () => {
        const fileKey = await openFileShareEnvelope(row.shareEnvelope, row.sharerSigningPublicKey, me.privateKey, {
          fileId: file.id,
          generation: row.keyGeneration,
          senderAccount: row.sharerAccount,
          senderIncarnationId: row.sharerIncarnationId,
          recipientAccount: me.account,
          recipientIncarnationId: me.incarnationId,
        })
        const metadata = current
          ? await openFileMetadataV1(file, fileKey)
          : await openFileMetadataV1(
              { id: file.id, keyGeneration: row.keyGeneration, metadataRevision: behind!.revision, metadataEnvelope: behind!.envelope },
              fileKey,
            )
        return { fileKey, metadata }
      })().catch(() => null)
      opened.set(cacheKey, pending)
    }
    result = await pending
  }
  const state: SharedFileState = !current ? 'waiting' : row.folderKeyCurrent ? 'ready' : 'editsWait'
  const driveFile = toDriveFile(file, result)
  // Waiting: named (as it was at the share's generation), but its current
  // content is under a key this account does not have yet.
  if (!current) driveFile.fileKey = null
  return {
    file: driveFile,
    container: {
      source: 'file',
      id: file.collectionId,
      parentId: null,
      name: null,
      key: null,
      keyEpoch: file.keyEpoch,
      ownerUserId: row.ownerUserId,
      ownerAuthorityPublicKey: '',
      epochStatementHash: '',
      nameRevision: 0,
      color: null,
      createdAt: file.createdAt,
      updatedAt: file.updatedAt ?? file.createdAt,
      ownerAccount: row.ownerAccount,
      remoteFileShareId: remoteShareId,
      canUpload: row.canEdit && state === 'ready',
      canDelete: false,
      canManage: false,
      isRoot: false,
    },
    canEdit: row.canEdit,
    canShare: row.canEdit && row.editorsCanShare && state === 'ready',
    state,
    ownerAccount: row.ownerAccount,
    sharedAt: row.sharedAt,
    remoteShareId,
  }
}

/** An accepted file from another server, as it is now there (checked by this server). */
interface RemoteFileShareNow {
  id: string
  remoteDomain: string
  file: FileRowLike
  shareEnvelope: string
  keyGeneration: number
  canEdit: boolean
  ownerUserId: string
  ownerAccount: string
  ownerIncarnationId: string
  ownerSigningPublicKey: string
  createdAt: string
}

interface RemoteFileShareRow {
  id: string
  remoteDomain: string
  remoteFileId: string
  ownerAccount: string
  createdAt: string
}

/**
 * A file shared from another server (docs/plans/drive-file-sharing.md,
 * slice 2): read, and edited live if shared for editing, through this
 * server (docs/plans/collab-federation.md). Only owners share across servers.
 */
async function openRemote(row: RemoteFileShareRow, me: DriveIdentity): Promise<SharedFile> {
  try {
    const { data } = await api.get<RemoteFileShareNow>(`/drive/federation/file-shares/${row.id}`)
    return await openShared(
      {
        file: data.file,
        shareEnvelope: data.shareEnvelope,
        canEdit: data.canEdit,
        keyGeneration: data.keyGeneration,
        folderKeyCurrent: true,
        ownerUserId: data.ownerUserId,
        ownerAccount: data.ownerAccount,
        ownerIncarnationId: data.ownerIncarnationId,
        ownerSigningPublicKey: data.ownerSigningPublicKey,
        sharerAccount: data.ownerAccount,
        sharerIncarnationId: data.ownerIncarnationId,
        sharerSigningPublicKey: data.ownerSigningPublicKey,
        editorsCanShare: false,
        sharedAt: data.createdAt,
      },
      me,
      row.id,
    )
  } catch {
    // No longer shared, or its server unreachable: listed, to be removed.
    const file = toDriveFile(
      {
        id: row.remoteFileId,
        collectionId: row.remoteFileId,
        metadataEnvelope: '',
        fileKeyEnvelope: '',
        keyEpoch: 1,
        keyGeneration: 1,
        metadataRevision: 1,
        encryptedSizeBytes: 0,
        createdAt: row.createdAt,
        originalKeyGeneration: 1,
        contentKeyGeneration: 1,
      },
      null,
    )
    return {
      file,
      container: {
        source: 'file', id: row.remoteFileId, parentId: null, name: null, key: null, keyEpoch: 1, ownerUserId: '',
        ownerAuthorityPublicKey: '', epochStatementHash: '', nameRevision: 0, color: null, createdAt: row.createdAt,
        updatedAt: row.createdAt, ownerAccount: row.ownerAccount, remoteFileShareId: row.id, canUpload: false,
        canDelete: false, canManage: false, isRoot: false,
      },
      canEdit: false,
      canShare: false,
      state: 'gone',
      ownerAccount: row.ownerAccount,
      sharedAt: row.createdAt,
      remoteShareId: row.id,
    }
  }
}

/** Files other people shared with you by themselves, here and from other servers. */
export function useSharedFiles({ enabled = true }: { enabled?: boolean } = {}) {
  const identity = useDriveIdentity()
  return useQuery({
    queryKey: [...sharedFilesKey, identity.data?.userId],
    enabled: enabled && identity.isSuccess,
    queryFn: async () => {
      const [{ data: local }, { data: remote }] = await Promise.all([
        api.get<SharedFileRow[]>('/shared-files'),
        api.get<RemoteFileShareRow[]>('/drive/federation/file-shares').catch(() => ({ data: [] as RemoteFileShareRow[] })),
      ])
      return Promise.all([
        ...local.map((row) => openShared(row, identity.data!)),
        ...remote.map((row) => openRemote(row, identity.data!)),
      ])
    },
  })
}

// -------------------------------------------------------------------- owner

export interface FileAccessMember {
  userId: string
  account: string
  accountIncarnationId: string
  drivePublicKey: string
  canEdit: boolean
  /** Below the file's, their access waits to be re-sealed. */
  keyGeneration: number
  createdAt: string
}

/** A public link to one file (its owner sees these). */
export interface FileLink {
  id: string
  token: string
  ownerLinkKeyEnvelope: string | null
  /** The generation its wrap opens; below the file's, it waits to be re-wrapped. */
  keyGeneration: number
  expiresAt: string | null
  createdAt: string
}

/** Someone on another server the file is shared with. */
export interface FederatedFileMember {
  id: string
  recipientUsername: string
  recipientServer: string
  recipientIncarnationId: string
  canEdit: boolean
  keyGeneration: number
  createdAt: string
}

export interface FileAccess {
  keyGeneration: number
  members: FileAccessMember[]
  federatedShares: FederatedFileMember[]
  /** People with edit access may share it on. */
  editorsCanShare: boolean
  publicLinks: FileLink[]
}

interface RemoteRecipient {
  account: string
  driveHpkePublicKey: string
  accountIncarnationId: string
}

/** Their Drive key through the signed federation lookup, still the same account incarnation. */
async function remoteRecipient(member: Pick<FederatedFileMember, 'recipientUsername' | 'recipientServer' | 'recipientIncarnationId'>): Promise<RemoteRecipient> {
  const { data } = await api.get<RemoteRecipient>(`/drive/federation/users/${encodeURIComponent(member.recipientUsername)}`, {
    params: { server: member.recipientServer },
  })
  if (data.accountIncarnationId !== member.recipientIncarnationId) throw new RecipientChanged(data.account)
  return data
}

function sealForRemote(me: DriveIdentity, file: DriveFile, key: Uint8Array, generation: number, to: RemoteRecipient) {
  return sealFor(me, file.id, key, generation, { account: to.account, accountIncarnationId: to.accountIncarnationId, drivePublicKey: to.driveHpkePublicKey })
}

/** A file link's key, from the owner's copy. */
function fileLinkKey(link: FileLink, me: DriveIdentity): Promise<Uint8Array> {
  if (!link.ownerLinkKeyEnvelope) return Promise.reject(new Error('no owner copy of this link'))
  return openOwnerLinkKeyV1(link.ownerLinkKeyEnvelope, me.masterKey, { linkId: link.id, ownerUserId: me.userId })
}

function wrapForLink(file: DriveFile, fileKey: Uint8Array, generation: number, linkKey: Uint8Array, me: DriveIdentity) {
  return sealPublicLinkFileKeyV1(fileKey, linkKey, { fileId: file.id, ownerUserId: me.userId, generation })
}

/** Where a link to one file opens: a document on Office, anything else in Drive. */
function fileLinkApp(name: string | null): 'drive' | 'office' {
  return name && opensInOffice(name) ? 'office' : 'drive'
}

/** The link to give people: the key rides in the fragment, never sent to a server. */
export async function fileLinkUrl(link: FileLink, me: DriveIdentity, fileName: string | null): Promise<string> {
  return publicLinkUrl(link.token, await fileLinkKey(link, me), fileLinkApp(fileName))
}

export const fileAccessKey = (fileId: string) => ['file-access', fileId] as const
export const pendingFileSharesKey = ['file-shares-pending'] as const

async function loadFileAccess(fileId: string): Promise<FileAccess> {
  return (await api.get<FileAccess>(`/files/${fileId}/access`)).data
}

/** Whether this account may share `file` by itself: it owns the folder. */
export function canShareFile(folder: Folder | undefined, file: DriveFile | undefined): boolean {
  return Boolean(folder?.source === 'owned' && folder.key && file?.fileKey && file.name)
}

/**
 * How this account may share a file: as its owner (add, change, remove), as
 * an editor the owner lets share (add people only), or not at all.
 */
export type ShareRole = 'owner' | 'editor'

export function shareRole(folder: Folder | undefined, file: DriveFile | undefined, shared?: SharedFile): ShareRole | null {
  if (canShareFile(folder, file)) return 'owner'
  return shared?.canShare && file?.fileKey ? 'editor' : null
}

export function useFileAccess(file: DriveFile | undefined, role: ShareRole | null) {
  return useQuery({
    queryKey: fileAccessKey(file?.id ?? ''),
    enabled: Boolean(file && role),
    refetchOnMount: 'always',
    queryFn: () => loadFileAccess(file!.id),
  })
}

/** The owner lets (or stops) editors share the file on. */
export function useSetEditorsCanShare() {
  const queryClient = useQueryClient()
  return useDriveMutation(async ({ file, value }: { file: DriveFile; value: boolean }) => {
    try {
      await api.put(`/files/${file.id}/sharing`, { editorsCanShare: value })
    } finally {
      await queryClient.invalidateQueries({ queryKey: fileAccessKey(file.id) })
    }
  })
}

function sealFor(me: DriveIdentity, fileId: string, key: Uint8Array, generation: number, to: { account: string; accountIncarnationId: string; drivePublicKey: string }) {
  return sealFileShareEnvelope(key, me.masterKey, to.drivePublicKey, {
    fileId,
    generation,
    senderAccount: me.account,
    senderIncarnationId: me.incarnationId,
    recipientAccount: to.account,
    recipientIncarnationId: to.accountIncarnationId,
  })
}

/**
 * The file at its folder's current key, with every share opening that key.
 * A file the folder moved past is re-keyed first (the key it is under is
 * held by someone who left the folder). Returns the file as it is now.
 */
export async function bringFileSharesUpToDate(folder: Folder, file: DriveFile, me: DriveIdentity): Promise<DriveFile> {
  const fresh = await rekeyFile(folder, file)
  if (!fresh.fileKey) throw new Error('file is not open')
  const access = await loadFileAccess(fresh.id)
  if (access.keyGeneration !== fresh.keyGeneration) throw new AccessChanged()
  const behind = access.members.filter((m) => m.keyGeneration < access.keyGeneration)
  const linksBehind = access.publicLinks.filter((l) => l.keyGeneration < access.keyGeneration)
  const remoteBehind = access.federatedShares.filter((f) => f.keyGeneration < access.keyGeneration)
  if (behind.length > 0 || linksBehind.length > 0 || remoteBehind.length > 0) {
    const members = await Promise.all(
      behind.map(async (m) => ({
        userId: m.userId,
        shareEnvelope: await sealFor(me, fresh.id, fresh.fileKey!, fresh.keyGeneration, m),
      })),
    )
    const publicLinks = await Promise.all(
      linksBehind.map(async (l) => ({
        id: l.id,
        keyEnvelope: await wrapForLink(fresh, fresh.fileKey!, fresh.keyGeneration, await fileLinkKey(l, me), me),
      })),
    )
    const federatedShares = await Promise.all(
      remoteBehind.map(async (f) => ({
        id: f.id,
        shareEnvelope: await sealForRemote(me, fresh, fresh.fileKey!, fresh.keyGeneration, await remoteRecipient(f)),
      })),
    )
    try {
      await api.put(`/files/${fresh.id}/shares`, { members, publicLinks, federatedShares })
    } catch (error) {
      if (isAxiosError(error) && error.response?.status === 409) throw new AccessChanged()
      throw error
    }
  }
  return fresh
}

interface LocalRecipient {
  userId: string
  account: string
  driveHpkePublicKey: string
  accountIncarnationId: string
}

export class CannotShareWithSelf extends Error {
  constructor() {
    super('a file is shared with someone else')
  }
}

/**
 * Share a file with someone on this server (by email), or change what they
 * may do with it. Across servers, files are not shared by themselves yet.
 */
/** Sharing gave someone here access, or made an invite for someone on another server. */
export type FileShareResult = { kind: 'local'; account: string } | { kind: 'federated'; account: string; inviteUrl: string }

export class OnlyOwnersShareAcross extends Error {
  constructor() {
    super('only the owner shares with other servers')
  }
}

/**
 * Share a file with someone here (their email), or change what they may do
 * with it; or with someone on another server (`user@server`), which returns
 * an invite link to send them. Across servers it is view only for now.
 */
export function useShareFile() {
  const queryClient = useQueryClient()
  return useDriveMutation(
    async (input: { folder: Folder; file: DriveFile; recipient: string; canEdit: boolean }, me): Promise<FileShareResult> => {
      const address = input.recipient.trim()
      const owner = canShareFile(input.folder, input.file)
      if (!owner && !(input.folder.source === 'file' && input.file.fileKey)) throw new Error('file is not open')
      let recipient: LocalRecipient | null = null
      try {
        recipient = (await api.get<LocalRecipient>(`/users/by-email/${encodeURIComponent(address)}`)).data
      } catch (error) {
        if (!(isAxiosError(error) && error.response?.status === 404)) throw error
      }
      try {
        if (!recipient) {
          // Not an account here: `user@server` on another Kutup server.
          const at = address.lastIndexOf('@')
          const username = address.slice(0, at)
          const server = address.slice(at + 1).toLowerCase()
          if (at < 1 || !server.includes('.')) throw new RecipientNotFound()
          if (!owner) throw new OnlyOwnersShareAcross()
          let remote: RemoteRecipient
          try {
            remote = (
              await api.get<RemoteRecipient>(`/drive/federation/users/${encodeURIComponent(username)}`, { params: { server } })
            ).data
          } catch (error) {
            if (isAxiosError(error) && error.response?.status === 404) throw new RecipientNotFound()
            throw error
          }
          const file = await bringFileSharesUpToDate(input.folder, input.file, me)
          const shareEnvelope = await sealForRemote(me, file, file.fileKey!, file.keyGeneration, remote)
          const { data } = await api.post<{ inviteUrl: string }>(`/files/${file.id}/federated-shares`, {
            recipientUsername: username,
            recipientServer: server,
            shareEnvelope,
            canEdit: input.canEdit,
          })
          return { kind: 'federated', account: remote.account, inviteUrl: data.inviteUrl }
        }
        if (recipient.userId === me.userId) throw new CannotShareWithSelf()
        // The owner first brings the file and its shares up to date; an editor
        // shares the key they hold (the server takes it only if it is current).
        const file = owner ? await bringFileSharesUpToDate(input.folder, input.file, me) : input.file
        const shareEnvelope = await sealFor(me, file.id, file.fileKey!, file.keyGeneration, {
          account: recipient.account,
          accountIncarnationId: recipient.accountIncarnationId,
          drivePublicKey: recipient.driveHpkePublicKey,
        })
        await api.post(`/files/${file.id}/share`, { recipientUserId: recipient.userId, shareEnvelope, canEdit: input.canEdit })
        return { kind: 'local', account: recipient.account }
      } finally {
        await queryClient.invalidateQueries({ queryKey: fileAccessKey(input.file.id) })
      }
    },
  )
}

/**
 * Make someone who has the file here a viewer or an editor (the owner
 * only). Their access is sealed again at the file's current key and the
 * server changes their permission in place; nobody is removed or re-added,
 * and no key changes hands that they did not already hold.
 */
export function useSetFileRole() {
  const queryClient = useQueryClient()
  return useDriveMutation(
    async (input: { folder: Folder; file: DriveFile; member: FileAccessMember; canEdit: boolean }, me) => {
      if (!canShareFile(input.folder, input.file)) throw new Error('only the owner changes what people may do')
      try {
        const file = await bringFileSharesUpToDate(input.folder, input.file, me)
        const shareEnvelope = await sealFor(me, file.id, file.fileKey!, file.keyGeneration, {
          account: input.member.account,
          accountIncarnationId: input.member.accountIncarnationId,
          drivePublicKey: input.member.drivePublicKey,
        })
        await api.post(`/files/${file.id}/share`, { recipientUserId: input.member.userId, shareEnvelope, canEdit: input.canEdit })
      } finally {
        await queryClient.invalidateQueries({ queryKey: fileAccessKey(input.file.id) })
      }
    },
  )
}

/** Stop seeing a file shared from another server. */
export function useLeaveRemoteFileShare() {
  return useDriveMutation(async (shared: SharedFile) => {
    if (!shared.remoteShareId) throw new Error('not a file from another server')
    await api.delete(`/drive/federation/file-shares/${shared.remoteShareId}`)
  })
}

/**
 * Remove people from a shared file: the file moves to a new key, wrapped at
 * its folder's current epoch and re-sealed for everyone who stays, in one
 * request. Built from access as it is now, so anyone added since stays.
 */
export function useRemoveFileAccess() {
  const queryClient = useQueryClient()
  return useDriveMutation(async (
    { folder, file, removed, removedLinks = [], removedFederated = [] }: { folder: Folder; file: DriveFile; removed: string[]; removedLinks?: string[]; removedFederated?: string[] },
    me,
  ) => {
    if (!canShareFile(folder, file)) throw new Error('file is not open')
    try {
      const access = await loadFileAccess(file.id)
      if (access.keyGeneration !== file.keyGeneration) throw new AccessChanged()
      const next = await rekeyFileRecordV1(
        { id: file.id, collectionId: file.collectionId, keyGeneration: file.keyGeneration, metadataRevision: file.metadataRevision },
        file.fileKey!,
        folder.keyEpoch,
        folder.key!,
        fileMetadataOf(file),
      )
      const members = await Promise.all(
        access.members
          .filter((m) => !removed.includes(m.userId))
          .map(async (m) => ({ userId: m.userId, shareEnvelope: await sealFor(me, file.id, next.fileKey, next.keyGeneration, m) })),
      )
      const publicLinks = await Promise.all(
        access.publicLinks
          .filter((l) => !removedLinks.includes(l.id))
          .map(async (l) => ({ id: l.id, keyEnvelope: await wrapForLink(file, next.fileKey, next.keyGeneration, await fileLinkKey(l, me), me) })),
      )
      const federatedShares = await Promise.all(
        access.federatedShares
          .filter((f) => !removedFederated.includes(f.id))
          .map(async (f) => ({ id: f.id, shareEnvelope: await sealForRemote(me, file, next.fileKey, next.keyGeneration, await remoteRecipient(f)) })),
      )
      await api.post(`/files/${file.id}/rotate`, {
        fromGeneration: file.keyGeneration,
        fileKeyEnvelope: next.fileKeyEnvelope,
        metadataEnvelope: next.metadataEnvelope,
        previousKeyEnvelope: next.previousKeyEnvelope,
        members,
        removed,
        publicLinks,
        removedLinks,
        federatedShares,
        removedFederated,
      })
    } catch (error) {
      if (isAxiosError(error) && error.response?.status === 409) throw new AccessChanged()
      throw error
    } finally {
      await queryClient.invalidateQueries({ queryKey: fileAccessKey(file.id) })
    }
  })
}

/**
 * The owner's side of keeping shares current: while Drive is open, files
 * whose shares were left behind (a folder member re-keyed the file, or the
 * folder moved to a new key) are brought up to date. Only the owner can:
 * the envelopes are signed with their key.
 */
export function useKeepFileSharesCurrent() {
  const identity = useDriveIdentity()
  const folders = useFolders()
  const queryClient = useQueryClient()
  const pending = useQuery({
    queryKey: pendingFileSharesKey,
    enabled: identity.isSuccess,
    refetchInterval: 60_000,
    queryFn: async () => (await api.get<{ fileId: string; collectionId: string }[]>('/file-shares/pending')).data,
  })
  useEffect(() => {
    const me = identity.data
    const index = folders.data
    if (!me || !index || !pending.data?.length) return
    let cancelled = false
    void (async () => {
      let changed = false
      const byFolder = new Map<string, string[]>()
      for (const p of pending.data) byFolder.set(p.collectionId, [...(byFolder.get(p.collectionId) ?? []), p.fileId])
      for (const [folderId, fileIds] of byFolder) {
        const folder = index.byId.get(folderId)
        if (cancelled || !folder || folder.source !== 'owned' || !folder.key) continue
        const files = await loadFolderFiles(folder).catch(() => [])
        for (const file of files.filter((f) => fileIds.includes(f.id))) {
          if (cancelled) return
          // Another tab or device may be at it too; the next round retries.
          await bringFileSharesUpToDate(folder, file, me).then(() => (changed = true), () => {})
        }
      }
      if (changed && !cancelled) {
        await Promise.all([
          queryClient.invalidateQueries({ queryKey: pendingFileSharesKey }),
          queryClient.invalidateQueries({ queryKey: ['files'] }),
        ])
      }
    })()
    return () => {
      cancelled = true
    }
  }, [identity.data, folders.data, pending.data, queryClient])
}

/**
 * Make a public link to one file (docs/plans/drive-file-sharing.md, slice 3):
 * a new link key wraps the file's current key; the owner keeps a copy of the
 * link key to copy the link again and keep it working across new keys.
 * Returns the link to give people.
 */
export function useCreateFileLink() {
  const queryClient = useQueryClient()
  return useDriveMutation(async ({ folder, file: listed }: { folder: Folder; file: DriveFile }, me): Promise<string> => {
    if (!canShareFile(folder, listed)) throw new Error('file is not open')
    const file = await bringFileSharesUpToDate(folder, listed, me)
    const linkKey = await generateKey()
    const id = crypto.randomUUID()
    try {
      const { data } = await api.post<{ token: string }>('/share', {
        shareType: 'file',
        targetId: file.id,
        collectionKeyEnvelope: await wrapForLink(file, file.fileKey!, file.keyGeneration, linkKey, me),
        id,
        ownerLinkKeyEnvelope: await sealOwnerLinkKeyV1(linkKey, me.masterKey, { linkId: id, ownerUserId: me.userId }),
      })
      return publicLinkUrl(data.token, linkKey, fileLinkApp(file.name))
    } finally {
      await queryClient.invalidateQueries({ queryKey: fileAccessKey(file.id) })
    }
  })
}
