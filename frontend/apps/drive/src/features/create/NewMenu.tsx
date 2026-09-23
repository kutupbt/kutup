import { FileSpreadsheet, FileText, FileType, FolderPlus, FolderUp, PenTool, Plus, Presentation, Upload } from 'lucide-react'
import { useRef, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { filesToFolderEntries } from '@kutup/files/upload/uploadFolder'
import { Button } from '@kutup/ui/components/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@kutup/ui/components/dropdown-menu'
import { useCurrentFolder } from '../drive/currentFolderContext'
import { loadFolderFiles } from '../drive/files'
import { useFolders } from '../drive/folders'
import { filePath } from '../drive/paths'
import { useCreateFolder } from '../drive/mutations'
import { NameDialog } from '../dialogs/NameDialog'
import { uploadOne, useUploadActions } from '../uploads/useUploadActions'
import { newDocumentFile, type NewDocument } from './templates'

const DOCUMENTS: { type: NewDocument; icon: ReactNode }[] = [
  { type: 'note', icon: <FileText /> },
  { type: 'document', icon: <FileType /> },
  { type: 'spreadsheet', icon: <FileSpreadsheet /> },
  { type: 'presentation', icon: <Presentation /> },
  { type: 'whiteboard', icon: <PenTool /> },
]

/**
 * The sidebar's New: into the folder on screen, or My Files elsewhere. Only
 * what the folder allows is offered — no subfolders in a folder shared with
 * you (the server refuses them), no documents in a folder on another server
 * (the editors cannot open it yet).
 */
export function NewMenu() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const current = useCurrentFolder()
  const folders = useFolders()
  const target = current ?? folders.data?.root ?? null
  const { uploadFiles, uploadDirectory, settled } = useUploadActions()
  const createFolder = useCreateFolder()
  const [naming, setNaming] = useState(false)
  const [creating, setCreating] = useState<NewDocument | null>(null)
  const filesInput = useRef<HTMLInputElement>(null)
  const folderInput = useRef<HTMLInputElement>(null)

  if (!target?.key || !target.canUpload) {
    return (
      <Button variant="chrome" className="w-full justify-start border border-chrome-border" disabled>
        <Plus />
        {t('newMenu.new')}
      </Button>
    )
  }

  async function createDocument(type: NewDocument) {
    if (!target) return
    setCreating(type)
    try {
      const existing = await loadFolderFiles(target)
      const file = newDocumentFile(type, t(`newMenu.untitled.${type}`), existing.flatMap((f) => (f.name ? [f.name] : [])))
      const id = await uploadOne(target, file)
      settled()
      if (id) void navigate(filePath(target, id))
    } catch {
      toast.error(t('newMenu.createFailed'))
    } finally {
      setCreating(null)
    }
  }

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="chrome" className="w-full justify-start border border-chrome-border" loading={creating !== null}>
            <Plus />
            {t('newMenu.new')}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" className="w-60">
          {target.canManage ? (
            <DropdownMenuItem onSelect={() => setNaming(true)}>
              <FolderPlus />
              {t('newMenu.folder')}
            </DropdownMenuItem>
          ) : null}
          <DropdownMenuItem onSelect={() => filesInput.current?.click()}>
            <Upload />
            {t('newMenu.uploadFiles')}
          </DropdownMenuItem>
          {target.canManage ? (
            <DropdownMenuItem onSelect={() => folderInput.current?.click()}>
              <FolderUp />
              {t('newMenu.uploadFolder')}
            </DropdownMenuItem>
          ) : null}
          {target.source !== 'remote' ? (
            <>
              <DropdownMenuSeparator />
              {DOCUMENTS.map(({ type, icon }) => (
                <DropdownMenuItem key={type} onSelect={() => void createDocument(type)}>
                  {icon}
                  {t(`newMenu.documents.${type}`)}
                </DropdownMenuItem>
              ))}
            </>
          ) : null}
        </DropdownMenuContent>
      </DropdownMenu>

      <input
        ref={filesInput}
        type="file"
        multiple
        hidden
        onChange={(e) => {
          const files = Array.from(e.target.files ?? [])
          e.target.value = ''
          if (files.length) uploadFiles(target, files)
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
          if (entries.length) uploadDirectory(target, entries, entries[0]?.relativePath[0] ?? files[0].name)
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
        onSubmit={(name) =>
          createFolder.mutate({ parent: target, name }, { onSuccess: () => setNaming(false) })
        }
      />
    </>
  )
}

