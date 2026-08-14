import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import api from '@/api/client'
import { useAppSelector } from '@/store'
import { selectMasterKey } from '@/store/authSlice'
import { openFileRecordV1, openOwnedCollectionKeyV1, openOwnedCollectionV1 } from '@/crypto'

/**
 * Trash data hook — single source of truth for the Trash UI (desktop table +
 * mobile list).
 *
 * `GET /api/trash` returns the caller's trash roots with their encrypted
 * metadata; like the Drive, everything decrypts client-side: the parent
 * collection key unwraps with the master key, the file key with the collection
 * key, and the `{name, mimeType, size}` metadata with the file key.
 *
 * Trash is owner-scoped (items live in the trash of the user who owns the
 * folder) and items keep counting against quota until purged — by the user or
 * by the server's retention sweeper (`TRASH_RETENTION_DAYS`, default 30).
 */

export interface TrashedFolder {
  id: string
  kind: 'folder'
  name: string
  color: string | null
  items: number
  deletedAt: string
}

export interface TrashedFile {
  id: string
  kind: 'file'
  name: string
  size: number
  mime: string
  deletedAt: string
}

export type TrashItem = TrashedFolder | TrashedFile

export interface UseTrashResult {
  items: TrashItem[]
  count: number
  isLoading: boolean
  restore: (id: string) => Promise<void>
  destroy: (id: string) => Promise<void>
  emptyAll: () => Promise<void>
}

interface TrashApiFolder {
  id: string
  ownerUserId: string
  nameEnvelope: string
  ownerKeyEnvelope: string
  keyEpoch: number
  nameRevision: number
  epochStatement: string
  epochStatementHash: string
  color: string | null
  items: number
  deletedAt: string
}

interface TrashApiFile {
  id: string
  collectionId: string
  metadataEnvelope: string
  fileKeyEnvelope: string
  keyEpoch: number
  metadataRevision: number
  collectionOwnerUserId: string
  collectionOwnerKeyEnvelope: string
  collectionKeyEpoch: number
  collectionEpochStatement: string
  collectionEpochStatementHash: string
  deletedAt: string
}

/**
 * Optional `onChanged` runs after any successful restore/destroy/empty —
 * Drive passes its manual reload here (its collections/files live in local
 * state, not React Query).
 */
export function useTrash(onChanged?: () => void): UseTrashResult {
  const { t } = useTranslation()
  const masterKey = useAppSelector(selectMasterKey)
  const qc = useQueryClient()

  const query = useQuery<TrashItem[]>({
    queryKey: ['trash'],
    enabled: !!masterKey,
    // Deletes happen outside this hook (Drive's delete handlers don't touch the
    // query cache), so the app-default staleTime: 30s would show a stale list to
    // anyone opening Trash right after deleting. Always refetch on mount.
    staleTime: 0,
    refetchOnMount: 'always',
    queryFn: async () => {
      const res = await api.get<{ folders: TrashApiFolder[]; files: TrashApiFile[] }>('/trash')

      const folders: TrashItem[] = await Promise.all(
        res.data.folders.map(async (f) => {
          let name = '[encrypted]'
          try {
            const opened = await openOwnedCollectionV1(f, masterKey!)
            name = opened.name
          } catch {
            // keep the placeholder
          }
          return {
            id: f.id,
            kind: 'folder' as const,
            name,
            color: f.color,
            items: f.items,
            deletedAt: f.deletedAt,
          }
        }),
      )

      const files: TrashItem[] = await Promise.all(
        res.data.files.map(async (f) => {
          let name = '[encrypted]'
          let size = 0
          let mime = ''
          try {
            const collectionKey = await openOwnedCollectionKeyV1({
              id: f.collectionId,
              ownerUserId: f.collectionOwnerUserId,
              ownerKeyEnvelope: f.collectionOwnerKeyEnvelope,
              keyEpoch: f.collectionKeyEpoch,
              epochStatement: f.collectionEpochStatement,
              epochStatementHash: f.collectionEpochStatementHash,
            }, masterKey!)
            const { metadata: meta } = await openFileRecordV1(f, collectionKey)
            name = meta.name
            size = meta.size ?? 0
            mime = meta.mimeType ?? ''
          } catch {
            // keep the placeholders
          }
          return { id: f.id, kind: 'file' as const, name, size, mime, deletedAt: f.deletedAt }
        }),
      )

      return [...folders, ...files].sort((a, b) => b.deletedAt.localeCompare(a.deletedAt))
    },
  })

  const refresh = () => {
    qc.invalidateQueries({ queryKey: ['trash'] })
    qc.invalidateQueries({ queryKey: ['collections'] })
    qc.invalidateQueries({ queryKey: ['files'] })
    onChanged?.()
  }

  const restoreMutation = useMutation({
    mutationFn: (id: string) => api.post(`/trash/${id}/restore`),
    onSuccess: () => {
      toast.success(t('trash.toast.restored', 'Restored'))
      refresh()
    },
    onError: (err: any) => {
      const msg =
        err.response?.status === 409
          ? t('trash.toast.restoreParentFirst', 'Restore the parent folder first')
          : err.response?.data?.error ?? t('trash.toast.restoreFailed', 'Restore failed')
      toast.error(msg)
    },
  })

  const destroyMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/trash/${id}`),
    onSuccess: () => {
      toast.success(t('trash.toast.deleted', 'Deleted forever'))
      refresh()
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error ?? t('trash.toast.deleteFailed', 'Delete failed'))
    },
  })

  const emptyMutation = useMutation({
    mutationFn: () => api.delete('/trash'),
    onSuccess: () => {
      toast.success(t('trash.toast.emptied', 'Trash emptied'))
      refresh()
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error ?? t('trash.toast.deleteFailed', 'Delete failed'))
    },
  })

  const items = query.data ?? []
  return {
    items,
    count: items.length,
    isLoading: query.isLoading,
    restore: async (id) => {
      await restoreMutation.mutateAsync(id)
    },
    destroy: async (id) => {
      await destroyMutation.mutateAsync(id)
    },
    emptyAll: async () => {
      await emptyMutation.mutateAsync()
    },
  }
}
