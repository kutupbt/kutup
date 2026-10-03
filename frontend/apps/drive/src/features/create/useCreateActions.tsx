import { FileSpreadsheet, FileText, FileType, FolderPlus, FolderUp, MapPin, PenTool, Presentation, Upload } from 'lucide-react'
import { useRef, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { filesToFolderEntries } from '@kutup/files/upload/uploadFolder'
import { NameDialog } from '../dialogs/NameDialog'
import { loadFolderFiles } from '@kutup/drive-core/files'
import type { Folder } from '@kutup/drive-core/model'
import { useCreateFolder } from '@kutup/drive-core/mutations'
import { openFile } from '../drive/paths'
import type { ExplorerAction } from '../explorer/Explorer'
import { uploadOne, useUploadActions } from '../uploads/useUploadActions'
import { newDocumentFile, type NewDocument } from './templates'

const DOCUMENTS: { type: NewDocument; icon: ReactNode }[] = [
  { type: 'note', icon: <FileText /> },
  { type: 'document', icon: <FileType /> },
  { type: 'spreadsheet', icon: <FileSpreadsheet /> },
  { type: 'presentation', icon: <Presentation /> },
  { type: 'whiteboard', icon: <PenTool /> },
  { type: 'map', icon: <MapPin /> },
]

/**
 * What can be made in a folder: a subfolder, uploads, new documents. Shared
 * by the sidebar's New button and the right-click menu on empty space, so
 * both offer exactly the same things. Only what the folder allows is
 * offered — no subfolders in a folder shared with you (the server refuses
 * them), no documents in a folder on another server (the editors cannot
 * open it yet).
 *
 * `elements` (the file pickers and the folder-name dialog) must be rendered
 * by the caller.
 */
export function useCreateActions(target: Folder | null): {
  actions: ExplorerAction[]
  busy: boolean
  elements: ReactNode
} {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const { uploadFiles, uploadDirectory, settled } = useUploadActions()
  const createFolder = useCreateFolder()
  const [naming, setNaming] = useState(false)
  const [creating, setCreating] = useState<NewDocument | null>(null)
  const filesInput = useRef<HTMLInputElement>(null)
  const folderInput = useRef<HTMLInputElement>(null)

  if (!target?.key || !target.canUpload) return { actions: [], busy: false, elements: null }
  const folder = target

  async function createDocument(type: NewDocument) {
    setCreating(type)
    try {
      const existing = await loadFolderFiles(folder)
      const file = newDocumentFile(type, t(`newMenu.untitled.${type}`), existing.flatMap((f) => (f.name ? [f.name] : [])))
      const uploaded = await uploadOne(folder, file)
      settled()
      if (uploaded) openFile(navigate, folder, { id: uploaded.fileId, name: file.name })
    } catch {
      toast.error(t('newMenu.createFailed'))
    } finally {
      setCreating(null)
    }
  }

  const actions: ExplorerAction[] = []
  if (folder.canManage) {
    actions.push({ id: 'new-folder', label: t('newMenu.folder'), icon: <FolderPlus />, onSelect: () => setNaming(true) })
  }
  actions.push({ id: 'upload-files', label: t('newMenu.uploadFiles'), icon: <Upload />, onSelect: () => filesInput.current?.click() })
  if (folder.canManage) {
    actions.push({ id: 'upload-folder', label: t('newMenu.uploadFolder'), icon: <FolderUp />, onSelect: () => folderInput.current?.click() })
  }
  if (folder.source !== 'remote') {
    DOCUMENTS.forEach(({ type, icon }, i) =>
      actions.push({
        id: `new-${type}`,
        label: t(`newMenu.documents.${type}`),
        icon,
        onSelect: () => void createDocument(type),
        separated: i === 0,
      }),
    )
  }

  const elements = (
    <>
      <input
        ref={filesInput}
        type="file"
        multiple
        hidden
        onChange={(e) => {
          const files = Array.from(e.target.files ?? [])
          e.target.value = ''
          if (files.length) uploadFiles(folder, files)
        }}
      />
      <input
        ref={folderInput}
        type="file"
        hidden
        // Non-standard but universal: pick a directory, get its files with relative paths.
        {...({ webkitdirectory: '' } as Record<string, string>)}
        onChange={(e) => {
          const files = Array.from(e.target.files ?? [])
          e.target.value = ''
          const entries = filesToFolderEntries(files)
          if (entries.length) uploadDirectory(folder, entries, entries[0]?.relativePath[0] ?? files[0].name)
        }}
      />
      <NameDialog
        open={naming}
        title={t('newMenu.folderTitle')}
        initial={t('newMenu.untitledFolder')}
        submit={t('newMenu.create')}
        pending={createFolder.isPending}
        error={createFolder.error}
        onClose={() => {
          setNaming(false)
          createFolder.reset()
        }}
        onSubmit={(name) => createFolder.mutate({ parent: folder, name }, { onSuccess: () => setNaming(false) })}
      />
    </>
  )

  return { actions, busy: creating !== null, elements }
}
