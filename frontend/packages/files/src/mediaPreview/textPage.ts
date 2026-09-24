// Where each line of a text thumbnail goes. Pure (no canvas), so it runs in
// the worker and in tests alike. Widths are estimated from the font size —
// good enough to wrap a preview, which only has to look like the page.

export interface PageLine {
  text: string
  y: number
  size: number
  bold: boolean
  /** A horizontal rule (Markdown `---`) instead of text. */
  rule?: boolean
}

export interface PageLayout {
  margin: number
  lines: PageLine[]
}

/** Average glyph width as a fraction of the font size. */
const CHAR_WIDTH = { prose: 0.5, code: 0.6 } as const

export function layoutTextPage(text: string, mode: 'prose' | 'code', width: number, height: number): PageLayout {
  const margin = Math.round(width * 0.08)
  // Big enough to read at card size, where a page shows at about half scale.
  const body = Math.max(6, Math.round(width / (mode === 'code' ? 26 : 28)))
  const usable = width - margin * 2
  const lines: PageLine[] = []
  let y = margin
  const bottom = height - margin / 2

  // Only the start of the file can show; do not scan a huge one.
  const source = text.slice(0, 8192).replace(/\r\n?/g, '\n').split('\n')
  for (const raw of source) {
    if (y >= bottom) break
    let size = body
    let bold = false
    let content = raw.replace(/\t/g, '  ')
    if (mode === 'prose') {
      const heading = /^(#{1,6})\s+(.*)$/.exec(content)
      if (heading) {
        const level = heading[1]!.length
        size = Math.round(body * (level === 1 ? 1.7 : level === 2 ? 1.4 : 1.15))
        bold = true
        content = heading[2]!
      } else if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(content)) {
        lines.push({ text: '', y: y + Math.round(body / 2), size: body, bold: false, rule: true })
        y += body * 1.5
        continue
      }
    }
    const perLine = Math.max(4, Math.floor(usable / (size * CHAR_WIDTH[mode])))
    // Code keeps its lines (cut, not wrapped); prose wraps at spaces.
    const pieces = content === '' ? [''] : mode === 'code' ? [content.slice(0, perLine)] : wrap(content, perLine)
    for (const piece of pieces) {
      if (y >= bottom) break
      lines.push({ text: piece, y, size, bold })
      y += Math.round(size * (mode === 'code' ? 1.35 : 1.45))
    }
    if (bold) y += Math.round(size * 0.25)
  }
  return { margin, lines }
}

function wrap(line: string, perLine: number): string[] {
  const out: string[] = []
  let current = ''
  for (const word of line.split(/\s+/).filter(Boolean)) {
    if (word.length > perLine) {
      if (current) out.push(current)
      for (let i = 0; i < word.length; i += perLine) out.push(word.slice(i, i + perLine))
      current = ''
      continue
    }
    const next = current ? `${current} ${word}` : word
    if (next.length > perLine) {
      out.push(current)
      current = word
    } else {
      current = next
    }
  }
  if (current) out.push(current)
  return out.length ? out : ['']
}
