import {
  AlignLeft,
  Archive,
  Code,
  File,
  FileText,
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
import type { FileKind } from '@kutup/drive-core/kinds'

/** The symbol on each kind's tile (`KindIcon`, `kindTileSvg`). */
export const KIND_GLYPHS: Record<FileKind, LucideIcon> = {
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
