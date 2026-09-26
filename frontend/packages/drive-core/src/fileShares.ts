import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect } from 'react'
import { isAxiosError } from 'axios'
import { openFileMetadataV1, openFileShareEnvelope, rekeyFileRecordV1, sealFileShareEnvelope } from '@kutup/crypto'
import api from '@kutup/session/client'
import { useDriveIdentity, type DriveIdentity } from './identity'
import { AccessChanged } from './access'
import { loadFolderFiles, toDriveFile, type FileRowLike } from './files'
import { useFolders } from './folders'
import { useDriveMutation, RecipientNotFound } from './mutations'
import { rekeyFile } from './rekey'
import type { DriveFile, Folder } from './model'

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
 */
export type SharedFileState = 'ready' | 'editsWait' | 'waiting'

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
}

export const sharedFilesKey = ['shared-files'] as const

type Opened = { fileKey: Uint8Array; metadata: { name: string; mimeType: string; size: number } } | null

const opened = new Map<string, Promise<Opened>>()

async function openShared(row: SharedFileRow, me: DriveIdentity): Promise<SharedFile> {
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
  }
}

/** Files other people here shared with you by themselves. */
export function useSharedFiles({ enabled = true }: { enabled?: boolean } = {}) {
  const identity = useDriveIdentity()
  return useQuery({
    queryKey: [...sharedFilesKey, identity.data?.userId],
    enabled: enabled && identity.isSuccess,
    queryFn: async () => {
      const { data } = await api.get<SharedFileRow[]>('/shared-files')
      return Promise.all(data.map((row) => openShared(row, identity.data!)))
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

export interface FileAccess {
  keyGeneration: number
  members: FileAccessMember[]
  /** People with edit access may share it on. */
  editorsCanShare: boolean
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
  if (behind.length > 0) {
    const members = await Promise.all(
      behind.map(async (m) => ({
        userId: m.userId,
        shareEnvelope: await sealFor(me, fresh.id, fresh.fileKey!, fresh.keyGeneration, m),
      })),
    )
    try {
      await api.put(`/files/${fresh.id}/shares`, { members })
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
export function useShareFile() {
  const queryClient = useQueryClient()
  return useDriveMutation(
    async (input: { folder: Folder; file: DriveFile; recipient: string; canEdit: boolean }, me) => {
      const email = input.recipient.trim()
      const owner = canShareFile(input.folder, input.file)
      if (!owner && !(input.folder.source === 'file' && input.file.fileKey)) throw new Error('file is not open')
      let recipient: LocalRecipient
      try {
        recipient = (await api.get<LocalRecipient>(`/users/by-email/${encodeURIComponent(email)}`)).data
      } catch (error) {
        if (isAxiosError(error) && error.response?.status === 404) throw new RecipientNotFound()
        throw error
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
      try {
        await api.post(`/files/${file.id}/share`, { recipientUserId: recipient.userId, shareEnvelope, canEdit: input.canEdit })
      } finally {
        await queryClient.invalidateQueries({ queryKey: fileAccessKey(file.id) })
      }
      return { account: recipient.account }
    },
  )
}

/**
 * Remove people from a shared file: the file moves to a new key, wrapped at
 * its folder's current epoch and re-sealed for everyone who stays, in one
 * request. Built from access as it is now, so anyone added since stays.
 */
export function useRemoveFileAccess() {
  const queryClient = useQueryClient()
  return useDriveMutation(async ({ folder, file, removed }: { folder: Folder; file: DriveFile; removed: string[] }, me) => {
    if (!canShareFile(folder, file)) throw new Error('file is not open')
    try {
      const access = await loadFileAccess(file.id)
      if (access.keyGeneration !== file.keyGeneration) throw new AccessChanged()
      const next = await rekeyFileRecordV1(
        { id: file.id, collectionId: file.collectionId, keyGeneration: file.keyGeneration, metadataRevision: file.metadataRevision },
        file.fileKey!,
        folder.keyEpoch,
        folder.key!,
        { name: file.name!, mimeType: file.mimeType, size: file.size },
      )
      const members = await Promise.all(
        access.members
          .filter((m) => !removed.includes(m.userId))
          .map(async (m) => ({ userId: m.userId, shareEnvelope: await sealFor(me, file.id, next.fileKey, next.keyGeneration, m) })),
      )
      await api.post(`/files/${file.id}/rotate`, {
        fromGeneration: file.keyGeneration,
        fileKeyEnvelope: next.fileKeyEnvelope,
        metadataEnvelope: next.metadataEnvelope,
        previousKeyEnvelope: next.previousKeyEnvelope,
        members,
        removed,
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
