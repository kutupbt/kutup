import {
  AlignLeft,
  Archive,
  Code,
  File,
  FileText,
  Folder,
  Image,
  Music,
  NotebookPen,
  PenTool,
  Play,
  Presentation,
  Sheet,
  MapPin,
  type LucideIcon,
} from 'lucide-react'
import { cn } from '@kutup/ui/lib/cn'
import type { FileKind, ItemKind } from '@kutup/drive-core/kinds'

const GLYPHS: Record<FileKind, LucideIcon> = {
  note: NotebookPen,
  document: AlignLeft,
  spreadsheet: Sheet,
  presentation: Presentation,
  whiteboard: PenTool,
  map: MapPin,
  pdf: FileText,
  image: Image,
  video: Play,
  audio: Music,
  code: Code,
  archive: Archive,
  other: File,
}

// Written out whole so Tailwind finds every class.
const TILES: Record<FileKind, string> = {
  note: 'bg-kind-note',
  document: 'bg-kind-document',
  spreadsheet: 'bg-kind-spreadsheet',
  presentation: 'bg-kind-presentation',
  whiteboard: 'bg-kind-whiteboard',
  map: 'bg-kind-map',
  pdf: 'bg-kind-pdf',
  image: 'bg-kind-image',
  video: 'bg-kind-video',
  audio: 'bg-kind-audio',
  code: 'bg-kind-code',
  archive: 'bg-kind-archive',
  other: 'bg-kind-other',
}

/**
 * What an item is, at a glance. Files are a filled tile in their kind's
 * colour (tokens.css, "file kinds") with a symbol on it, the convention
 * Google Drive taught everyone; folders are a filled folder, neutral unless
 * their owner gave them a colour. Size it with a `size-*` class; the glyph
 * scales with the tile.
 */
export function KindIcon({ kind, color, className }: { kind: ItemKind; color?: string | null; className?: string }) {
  if (kind === 'folder') {
    return (
      <Folder
        aria-hidden
        strokeWidth={1.5}
        // A folder's own colour is user data, applied as a style rather than a theme token.
        style={color ? { color, fill: color } : undefined}
        className={cn('shrink-0', !color && 'fill-kind-folder text-kind-folder', className)}
      />
    )
  }
  const Glyph = GLYPHS[kind]
  return (
    <span
      aria-hidden
      className={cn('inline-flex shrink-0 items-center justify-center rounded-[22%] text-kind-glyph', TILES[kind], className)}
    >
      <Glyph className="size-[62%]" strokeWidth={2.25} fill={kind === 'video' ? 'currentColor' : 'none'} />
    </span>
  )
}
