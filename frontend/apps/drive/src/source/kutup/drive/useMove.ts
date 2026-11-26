import { useQueryClient } from '@tanstack/react-query'
import { useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { loadFolderFiles } from '@kutup/drive-core/files'
import { foldersKey, type FolderIndex } from '@kutup/drive-core/folders'
import type { Folder } from '@kutup/drive-core/model'
import { clashes, moveFile, moveFolder, moveRefusal, MoveConflictError, MoveNameTakenError, type MoveSource } from './move'

/**
 * Move files and folders into `dest`, then say what happened with an undo
 * that moves them back. Items whose name is already taken in `dest` stay
 * where they are (as in Proton Drive: a move never renames or overwrites).
 */
export function useMove() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()

  const refresh = useCallback(
    () =>
      Promise.all([
        queryClient.invalidateQueries({ queryKey: foldersKey }),
        queryClient.invalidateQueries({ queryKey: ['files'] }),
      ]),
    [queryClient],
  )

  /** Move each back to where it came from: a file from `dest` to its old folder. */
  const undo = useCallback(
    async (index: FolderIndex, moved: MoveSource[], dest: Folder) => {
      const files = moved.some((m) => m.file) ? await loadFolderFiles(dest) : []
      for (const item of moved) {
        if (item.file) {
          const now = files.find((f) => f.id === item.file.id)
          if (!now) throw new Error('moved file not found')
          await moveFile(dest, now, item.folder)
        } else {
          const parent = item.folder.parentId ? (index.byId.get(item.folder.parentId) ?? null) : null
          await moveFolder(item.folder, parent)
        }
      }
    },
    [],
  )

  return useCallback(
    async (index: FolderIndex, sources: MoveSource[], dest: Folder) => {
      const destName = dest.isRoot ? t('nav.myFiles') : (dest.name ?? t('drive.encrypted'))
      const movable = sources.filter((s) => moveRefusal(index, s, dest) === null)
      const taken = await clashes(index, movable, dest)
      const moved: MoveSource[] = []
      let changed = 0
      let failed = 0
      for (const source of movable) {
        if (taken.has(source)) continue
        try {
          if (source.file) await moveFile(source.folder, source.file, dest)
          else await moveFolder(source.folder, dest)
          moved.push(source)
        } catch (error) {
          // Taken meanwhile (or by an item not listed yet): stays, as above.
          if (error instanceof MoveNameTakenError) taken.add(source)
          else if (error instanceof MoveConflictError) changed += 1
          else failed += 1
        }
      }
      await refresh()

      if (taken.size > 0) {
        const only = [...taken][0]
        toast.error(
          taken.size === 1 && only
            ? t('dialogs.move.nameTaken', { name: only.file ? only.file.name : only.folder.name, folder: destName })
            : t('dialogs.move.namesTaken', { count: taken.size, folder: destName }),
        )
      }
      if (changed > 0) toast.error(t('dialogs.move.changed', { count: changed }))
      if (failed > 0) toast.error(t('dialogs.move.failed', { count: failed }))
      if (moved.length === 0) return
      toast.success(t('dialogs.move.done', { count: moved.length, folder: destName }), {
        action: {
          label: t('drive.undo'),
          onClick: () => {
            void undo(index, moved, dest)
              .catch(() => toast.error(t('dialogs.move.undoFailed')))
              .finally(() => void refresh())
          },
        },
      })
    },
    [refresh, undo, t],
  )
}
