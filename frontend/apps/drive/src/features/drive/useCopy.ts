import { useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { classifyUploadError } from '../uploads/uploadError'
import { uploads } from '../uploads/uploadStore'
import { useUploadActions } from '../uploads/useUploadActions'
import { copyFile, copyFolder, copyName, countFiles, namesIn } from './copy'
import type { FolderIndex } from '@kutup/drive-core/folders'
import { useDriveIdentity } from '@kutup/drive-core/identity'
import type { DriveFile, Folder } from '@kutup/drive-core/model'

export type CopySource = { folder: Folder; file?: undefined } | { folder: Folder; file: DriveFile }

/**
 * Copy files and folders into `dest`. Each item becomes one entry in the
 * upload panel, with progress and cancel, because that is what a copy is
 * here: a download and a fresh encrypted upload. Name clashes in the
 * destination get "(1)", "(2)"… rather than overwriting.
 */
export function useCopy() {
  const { t } = useTranslation()
  const identity = useDriveIdentity()
  const { settled } = useUploadActions()

  return useCallback(
    async (index: FolderIndex, sources: CopySource[], dest: Folder) => {
      const me = identity.data
      if (!me || !dest.key) return
      const taken = await namesIn(index, dest)
      const folderName = dest.isRoot ? t('nav.myFiles') : (dest.name ?? '')
      uploads.add(
        sources.map((source) => {
          const original = source.file ? source.file.name : source.folder.name
          const name = copyName(original ?? '', taken)
          taken.push(name)
          if (source.file) {
            const file = source.file
            return {
              name,
              folderName,
              total: file.size,
              run: (signal: AbortSignal, progress: (sent: number, total: number) => void) =>
                copyFile({ folder: source.folder, file }, dest, name, signal, progress),
            }
          }
          return {
            name,
            folderName,
            total: 1,
            unit: 'files' as const,
            run: async (signal: AbortSignal, progress: (sent: number, total: number) => void) => {
              const total = Math.max(1, await countFiles(index, source.folder))
              let done = 0
              progress(0, total)
              await copyFolder(me, index, source.folder, dest, name, signal, () => progress(++done, total))
              progress(total, total)
            },
          }
        }),
        settled,
        classifyUploadError,
      )
    },
    [identity.data, settled, t],
  )
}
