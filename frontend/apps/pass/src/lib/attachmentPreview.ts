/** What an attachment preview can show, by the attachment's name. */

export const IMAGE_TYPES: Record<string, string> = {
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  webp: 'image/webp',
  bmp: 'image/bmp',
  // An SVG shown as an <img> runs no script.
  svg: 'image/svg+xml',
}
const TEXT_EXTENSIONS = new Set(['txt', 'text', 'md', 'log', 'csv', 'tsv', 'json', 'xml', 'yaml', 'yml', 'toml', 'ini', 'conf', 'cfg', 'pem', 'crt', 'cer', 'pub', 'key', 'asc', 'sh', 'env'])

export function extension(name: string): string {
  const dot = name.lastIndexOf('.')
  return dot > 0 ? name.slice(dot + 1).toLowerCase() : ''
}

/** What a preview can show of an attachment by its name: an image, text, or nothing. */
export function previewKind(name: string): 'image' | 'text' | null {
  const ext = extension(name)
  if (ext in IMAGE_TYPES) return 'image'
  if (TEXT_EXTENSIONS.has(ext)) return 'text'
  return null
}
