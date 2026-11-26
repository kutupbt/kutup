// What a Drive item is, for its icon, the type filter and the type sort. Names
// and MIME types are decrypted client-side; the extension decides where the
// two disagree, because it is what the user chose and what opens the file.

export const FILE_KINDS = [
  'note',
  'document',
  'spreadsheet',
  'presentation',
  'whiteboard',
  'map',
  'pdf',
  'image',
  'video',
  'audio',
  'code',
  'archive',
  'other',
] as const
export type FileKind = (typeof FILE_KINDS)[number]
export type ItemKind = 'folder' | FileKind

const BY_EXTENSION: Record<string, FileKind> = {
  md: 'note', markdown: 'note', txt: 'note',
  docx: 'document', doc: 'document', odt: 'document', rtf: 'document',
  xlsx: 'spreadsheet', xls: 'spreadsheet', ods: 'spreadsheet', csv: 'spreadsheet',
  pptx: 'presentation', ppt: 'presentation', odp: 'presentation',
  excalidraw: 'whiteboard',
  kutupmap: 'map',
  pdf: 'pdf',
  png: 'image', jpg: 'image', jpeg: 'image', gif: 'image', webp: 'image', avif: 'image', svg: 'image', heic: 'image', heif: 'image', bmp: 'image', tif: 'image', tiff: 'image',
  // Camera RAW: previews come from the JPEG they embed (docs/plans/photos.md).
  dng: 'image', cr2: 'image', cr3: 'image', nef: 'image', nrw: 'image', arw: 'image', orf: 'image', rw2: 'image', pef: 'image', srw: 'image', raf: 'image',
  mp4: 'video', webm: 'video', mov: 'video', mkv: 'video', m4v: 'video',
  mp3: 'audio', wav: 'audio', ogg: 'audio', oga: 'audio', m4a: 'audio', flac: 'audio', opus: 'audio',
  zip: 'archive', tar: 'archive', gz: 'archive', tgz: 'archive', '7z': 'archive', rar: 'archive', xz: 'archive', zst: 'archive',
  js: 'code', jsx: 'code', ts: 'code', tsx: 'code', json: 'code', py: 'code', rs: 'code', go: 'code', java: 'code',
  c: 'code', h: 'code', cpp: 'code', hpp: 'code', cs: 'code', rb: 'code', php: 'code', sh: 'code', sql: 'code',
  html: 'code', css: 'code', scss: 'code', xml: 'code', yaml: 'code', yml: 'code', toml: 'code', ini: 'code',
  kt: 'code', swift: 'code', lua: 'code', dart: 'code', vue: 'code', svelte: 'code',
}

export function extensionOf(name: string): string {
  const dot = name.lastIndexOf('.')
  return dot > 0 ? name.slice(dot + 1).toLowerCase() : ''
}

export function fileKind(name: string, mimeType?: string | null): FileKind {
  const byExtension = BY_EXTENSION[extensionOf(name)]
  if (byExtension) return byExtension
  const mime = (mimeType ?? '').toLowerCase()
  if (mime.startsWith('image/')) return 'image'
  if (mime.startsWith('video/')) return 'video'
  if (mime.startsWith('audio/')) return 'audio'
  if (mime === 'application/pdf') return 'pdf'
  if (mime.startsWith('text/')) return 'note'
  return 'other'
}
