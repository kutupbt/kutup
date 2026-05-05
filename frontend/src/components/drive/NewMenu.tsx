import { FolderPlus, FileText, FileSpreadsheet, Presentation, Upload as UploadIcon, Globe } from 'lucide-react'
import {
  DropdownMenuItem,
  DropdownMenuSeparator,
} from '@/components/ui/dropdown-menu'

export type OfficeKind = 'docx' | 'xlsx' | 'pptx'

export interface NewMenuActions {
  onNewFolder: () => void
  onNewNote: () => void
  onNewOffice?: (kind: OfficeKind) => void
  onUpload?: () => void
  onAddRemote?: () => void
}

interface NewMenuItemsProps extends NewMenuActions {
  /** Show the Upload entry (omit when the topbar already has its own button). */
  showUpload?: boolean
  /** Show the federated "Add remote share" entry. */
  showAddRemote?: boolean
  /** Show the OnlyOffice doc / sheet / slide entries. Hidden when the
   *  integration isn't installed; default true. */
  showOffice?: boolean
}

export function NewMenuItems({
  onNewFolder,
  onNewNote,
  onNewOffice,
  onUpload,
  onAddRemote,
  showUpload = false,
  showAddRemote = true,
  showOffice = true,
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
      {showOffice && onNewOffice && (
        <>
          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={() => onNewOffice('docx')}>
            <FileText className="mr-2 h-4 w-4 text-blue-500" />
            Document (.docx)
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => onNewOffice('xlsx')}>
            <FileSpreadsheet className="mr-2 h-4 w-4 text-emerald-500" />
            Spreadsheet (.xlsx)
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => onNewOffice('pptx')}>
            <Presentation className="mr-2 h-4 w-4 text-orange-500" />
            Presentation (.pptx)
          </DropdownMenuItem>
        </>
      )}
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
