import {
  File,
  FileText,
  FileSpreadsheet,
  Image as ImageIcon,
  Music,
  Video,
  Archive,
  Presentation,
  Pencil,
} from 'lucide-react'
import { cn } from '@/lib/utils'

type IconKind =
  | 'spreadsheet'
  | 'doc-blue'
  | 'pptx'
  | 'pdf'
  | 'image'
  | 'text'
  | 'audio'
  | 'video'
  | 'archive'
  | 'whiteboard'
  | 'generic'

const ICON_BY_EXT: Record<string, IconKind> = {
  xlsx: 'spreadsheet', xls: 'spreadsheet', csv: 'spreadsheet', ods: 'spreadsheet',
  docx: 'doc-blue', doc: 'doc-blue', odt: 'doc-blue',
  pptx: 'pptx', ppt: 'pptx', odp: 'pptx',
  pdf: 'pdf',
  png: 'image', jpg: 'image', jpeg: 'image', gif: 'image', webp: 'image', svg: 'image', bmp: 'image', heic: 'image',
  txt: 'text', md: 'text', log: 'text',
  mp3: 'audio', wav: 'audio', flac: 'audio', ogg: 'audio', m4a: 'audio',
  mp4: 'video', mov: 'video', webm: 'video', mkv: 'video', avi: 'video',
  zip: 'archive', tar: 'archive', gz: 'archive', '7z': 'archive', rar: 'archive',
  excalidraw: 'whiteboard',
}

const KIND_PRESET: Record<IconKind, { Icon: typeof File; tone: string }> = {
  spreadsheet: { Icon: FileSpreadsheet, tone: 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400' },
  'doc-blue':  { Icon: FileText,        tone: 'bg-blue-500/15 text-blue-600 dark:text-blue-400' },
  pptx:        { Icon: Presentation,    tone: 'bg-orange-500/15 text-orange-600 dark:text-orange-400' },
  pdf:         { Icon: FileText,        tone: 'bg-red-500/15 text-red-600 dark:text-red-400' },
  image:       { Icon: ImageIcon,       tone: 'bg-sky-500/15 text-sky-600 dark:text-sky-400' },
  text:        { Icon: FileText,        tone: 'bg-muted text-muted-foreground' },
  audio:       { Icon: Music,           tone: 'bg-pink-500/15 text-pink-600 dark:text-pink-400' },
  video:       { Icon: Video,           tone: 'bg-purple-500/15 text-purple-600 dark:text-purple-400' },
  archive:     { Icon: Archive,         tone: 'bg-amber-500/15 text-amber-600 dark:text-amber-400' },
  whiteboard:  { Icon: Pencil,          tone: 'bg-pink-500/15 text-pink-600 dark:text-pink-400' },
  generic:     { Icon: File,            tone: 'bg-muted text-muted-foreground' },
}

function kindFor(filename: string): IconKind {
  const dot = filename.lastIndexOf('.')
  if (dot < 0) return 'generic'
  const ext = filename.slice(dot + 1).toLowerCase()
  return ICON_BY_EXT[ext] ?? 'generic'
}

interface FileIconProps {
  filename: string
  size?: 'sm' | 'md' | 'lg'
  className?: string
}

const SIZE = {
  sm: { box: 'h-7 w-7 rounded-md', icon: 'h-3.5 w-3.5' },
  md: { box: 'h-9 w-9 rounded-lg', icon: 'h-4 w-4' },
  lg: { box: 'h-12 w-12 rounded-xl', icon: 'h-5 w-5' },
}

export default function FileIcon({ filename, size = 'sm', className }: FileIconProps) {
  const kind = kindFor(filename)
  const { Icon, tone } = KIND_PRESET[kind]
  const s = SIZE[size]
  return (
    <div className={cn('inline-flex items-center justify-center', s.box, tone, className)}>
      <Icon className={s.icon} />
    </div>
  )
}
