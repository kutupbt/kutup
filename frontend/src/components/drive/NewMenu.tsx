import { FolderPlus, FileText, Upload as UploadIcon, Globe } from 'lucide-react'
import {
  DropdownMenuItem,
  DropdownMenuSeparator,
} from '@/components/ui/dropdown-menu'

export interface NewMenuActions {
  onNewFolder: () => void
  onNewNote: () => void
  onUpload?: () => void
  onAddRemote?: () => void
}

interface NewMenuItemsProps extends NewMenuActions {
  /** Show the Upload entry (omit when the topbar already has its own button). */
  showUpload?: boolean
  /** Show the federated "Add remote share" entry. */
  showAddRemote?: boolean
}

export function NewMenuItems({
  onNewFolder,
  onNewNote,
  onUpload,
  onAddRemote,
  showUpload = false,
  showAddRemote = true,
}: NewMenuItemsProps) {
  return (
    <>
      <DropdownMenuItem onSelect={onNewFolder}>
        <FolderPlus className="mr-2 h-4 w-4" />
        Folder
      </DropdownMenuItem>
      <DropdownMenuItem onSelect={onNewNote}>
        <FileText className="mr-2 h-4 w-4" />
        Note (.md)
      </DropdownMenuItem>
      {showUpload && onUpload && (
        <>
          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={onUpload}>
            <UploadIcon className="mr-2 h-4 w-4" />
            Upload files
          </DropdownMenuItem>
        </>
      )}
      {showAddRemote && onAddRemote && (
        <>
          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={onAddRemote}>
            <Globe className="mr-2 h-4 w-4" />
            Add remote share
          </DropdownMenuItem>
        </>
      )}
    </>
  )
}
