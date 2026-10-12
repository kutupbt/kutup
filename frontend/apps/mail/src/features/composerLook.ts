/** Proton's composer fonts (`FONT_FACES`): the setting's id, the label, the CSS family. */
export const FONT_FACES: { id: string; label: string; family: string }[] = [
  { id: 'sans-serif', label: 'Sans Serif', family: 'sans-serif' },
  { id: 'serif', label: 'Serif', family: 'serif' },
  { id: 'georgia', label: 'Georgia', family: 'Georgia, serif' },
  { id: 'arial', label: 'Arial', family: 'Arial, sans-serif' },
  { id: 'helvetica', label: 'Helvetica', family: 'Helvetica, sans-serif' },
  { id: 'monospace', label: 'Monospace', family: 'Menlo, Consolas, Courier New, monospace' },
  { id: 'tahoma', label: 'Tahoma', family: 'Tahoma, sans-serif' },
  { id: 'verdana', label: 'Verdana', family: 'Verdana, sans-serif' },
  { id: 'times', label: 'Times New Roman', family: 'Times New Roman, serif' },
  { id: 'trebuchet', label: 'Trebuchet MS', family: 'Trebuchet MS, sans-serif' },
]

/** Proton's font sizes, in pixels. */
export const FONT_SIZES = [10, 12, 14, 16, 18, 20, 22, 24, 26]

export interface ComposerLook {
  fontFace: string
  fontSize: number
  rtl: boolean
}

export const fontFamily = (id: string) => (FONT_FACES.find((f) => f.id === id) ?? FONT_FACES[3]).family

/**
 * The message's HTML as sent: wrapped with its font, size and direction,
 * as Proton's composer writes them, so other mail programs show it so.
 */
export function wrapHtml(html: string, look: ComposerLook): string {
  const style = `font-family: ${fontFamily(look.fontFace)}; font-size: ${look.fontSize}px;`
  return `<div style="${style}"${look.rtl ? ' dir="rtl"' : ''}>${html}</div>`
}

/** Plain text as editor HTML: escaped, a paragraph per line. */
export function plainToHtml(text: string): string {
  const escape = (line: string) => line.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]!)
  return text
    .split('\n')
    .map((line) => `<p>${escape(line)}</p>`)
    .join('')
}
