import {
  File,
  FileArchive,
  FileAudio,
  FileCode,
  FileImage,
  FileSpreadsheet,
  FileText,
  FileType,
  FileVideo,
  Folder,
  PenTool,
  Presentation,
  type LucideIcon,
} from 'lucide-react'
import { cn } from '@kutup/ui/lib/cn'
import type { ItemKind } from './kinds'

const ICONS: Record<ItemKind, LucideIcon> = {
  folder: Folder,
  note: FileText,
  document: FileType,
  spreadsheet: FileSpreadsheet,
  presentation: Presentation,
  whiteboard: PenTool,
  pdf: FileText,
  image: FileImage,
  video: FileVideo,
  audio: FileAudio,
  code: FileCode,
  archive: FileArchive,
  other: File,
}

/**
 * The kind's icon. Folders take the primary colour so they stand out in the
 * mixed list without being sorted apart; files stay neutral.
 */
export function KindIcon({ kind, color, className }: { kind: ItemKind; color?: string | null; className?: string }) {
  const Icon = ICONS[kind]
  return (
    <Icon
      aria-hidden
      // A folder's own colour is user data, applied as a style rather than a theme token.
      style={color ? { color, fill: `${color}26` } : undefined}
      className={cn('shrink-0', kind === 'folder' ? !color && 'fill-primary/15 text-primary' : 'text-muted-foreground', className)}
    />
  )
}
