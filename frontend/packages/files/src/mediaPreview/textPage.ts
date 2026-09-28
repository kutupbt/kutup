// Where each line of a text thumbnail goes. Pure (no canvas), so it runs in
// the worker and in tests alike. Widths are estimated from the font size —
// good enough to wrap a preview, which only has to look like the page.
//
// Notes (`prose`) are laid out as their Markdown reads: headings, fenced
// code in a shaded box, lists, task checkboxes, quotes, tables and rules,
// with inline marks (`**`, backticks, link targets) left out. Code files
// show as written.

export interface PageLine {
  text: string
  /** Where the text starts (list items and quotes are indented). */
  x: number
  y: number
  size: number
  bold: boolean
  /** Monospace (code files, and fenced code in notes). */
  mono?: boolean
  /** Softer ink (quotes, table rules). */
  muted?: boolean
  /** A horizontal rule (Markdown `---`) instead of text. */
  rule?: boolean
  /** Drawn before the text, at `markerX`: a bullet, a number, or a task box. */
  marker?: { kind: 'bullet' } | { kind: 'number'; text: string } | { kind: 'task'; checked: boolean }
  markerX?: number
}

/** A shaded rectangle behind fenced code, or a quote's bar. */
export interface PageBox {
  kind: 'code' | 'quote'
  x: number
  y: number
  width: number
  height: number
}

export interface PageLayout {
  margin: number
  lines: PageLine[]
  boxes: PageBox[]
}

/** Average glyph width as a fraction of the font size. */
const CHAR_WIDTH = { sans: 0.5, mono: 0.6 } as const

/** Links and images keep their text; emphasis and code marks go. */
export function stripInline(text: string): string {
  return text
    .replace(/!\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/(\*\*|__)(?=\S)(.+?)(?<=\S)\1/g, '$2')
    .replace(/(\*|_)(?=\S)(.+?)(?<=\S)\1/g, '$2')
    .replace(/~~(.+?)~~/g, '$1')
    .replace(/`([^`]+)`/g, '$1')
}

export function layoutTextPage(text: string, mode: 'prose' | 'code', width: number, height: number): PageLayout {
  const margin = Math.round(width * 0.08)
  // Big enough to read at card size, where a page shows at about half scale.
  const body = Math.max(6, Math.round(width / (mode === 'code' ? 26 : 22)))
  const lines: PageLine[] = []
  const boxes: PageBox[] = []
  let y = margin
  const bottom = height - margin / 2
  const right = width - margin
  const indent = Math.round(body * 1.4)

  const perLine = (x: number, size: number, mono: boolean) =>
    Math.max(4, Math.floor((right - x) / (size * CHAR_WIDTH[mono ? 'mono' : 'sans'])))
  const lineHeight = (size: number, mono: boolean) => Math.round(size * (mono ? 1.35 : 1.45))
  /** Wrapped (prose) or cut (code) lines of one paragraph line. */
  const place = (content: string, line: Omit<PageLine, 'text' | 'y'>) => {
    const mono = Boolean(line.mono)
    const room = perLine(line.x, line.size, mono)
    const pieces = content === '' ? [''] : mono ? [content.slice(0, room)] : wrap(content, room)
    pieces.forEach((piece, i) => {
      if (y >= bottom) return
      // The marker goes with the first piece only.
      lines.push({ ...line, ...(i > 0 ? { marker: undefined, markerX: undefined } : {}), text: piece, y })
      y += lineHeight(line.size, mono)
    })
  }

  // Only the start of the file can show; do not scan a huge one.
  const source = text.slice(0, 8192).replace(/\r\n?/g, '\n').split('\n')

  if (mode === 'code') {
    for (const raw of source) {
      if (y >= bottom) break
      place(raw.replace(/\t/g, '  '), { x: margin, size: body, bold: false, mono: true })
    }
    return { margin, lines, boxes }
  }

  const codeSize = Math.round(body * 0.88)
  const pad = Math.round(body * 0.5)
  let fence: { marker: string; top: number } | null = null
  let quoteTop: number | null = null
  const closeQuote = () => {
    if (quoteTop === null) return
    boxes.push({ kind: 'quote', x: margin, y: quoteTop, width: Math.max(2, Math.round(body / 5)), height: y - quoteTop })
    quoteTop = null
  }

  for (const raw of source) {
    if (y >= bottom) break
    const content = raw.replace(/\t/g, '  ')

    // Fenced code: a shaded box, monospace, the fences themselves unseen.
    const fenceMark = /^\s*(`{3,}|~{3,})/.exec(content)
    if (fence) {
      if (fenceMark && fenceMark[1]![0] === fence.marker[0] && fenceMark[1]!.length >= fence.marker.length) {
        y += pad
        boxes.push({ kind: 'code', x: margin, y: fence.top, width: right - margin, height: y - fence.top })
        fence = null
        y += Math.round(body * 0.4)
      } else {
        place(content, { x: margin + pad, size: codeSize, bold: false, mono: true })
      }
      continue
    }
    if (fenceMark) {
      closeQuote()
      fence = { marker: fenceMark[1]!, top: y }
      y += pad
      continue
    }

    const quote = /^\s*>\s?(.*)$/.exec(content)
    if (quote) {
      quoteTop ??= y
      place(stripInline(quote[1]!), { x: margin + indent, size: body, bold: false, muted: true })
      continue
    }
    closeQuote()

    const heading = /^(#{1,6})\s+(.*)$/.exec(content)
    if (heading) {
      const level = heading[1]!.length
      const size = Math.round(body * (level === 1 ? 1.7 : level === 2 ? 1.4 : 1.15))
      place(stripInline(heading[2]!), { x: margin, size, bold: true })
      y += Math.round(size * 0.25)
      continue
    }
    if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(content)) {
      lines.push({ text: '', x: margin, y: y + Math.round(body / 2), size: body, bold: false, rule: true })
      y += body * 1.5
      continue
    }

    // Lists: nested by leading spaces, two per level.
    const item = /^(\s*)([-*+]|\d{1,9}[.)])\s+(?:\[([ xX])\]\s+)?(.*)$/.exec(content)
    if (item) {
      const depth = Math.min(4, Math.floor(item[1]!.length / 2))
      const markerX = margin + depth * indent
      const marker: PageLine['marker'] =
        item[3] !== undefined
          ? { kind: 'task', checked: item[3] !== ' ' }
          : /\d/.test(item[2]!)
            ? { kind: 'number', text: item[2]! }
            : { kind: 'bullet' }
      place(stripInline(item[4]!), { x: markerX + indent, size: body, bold: false, marker, markerX })
      continue
    }

    // Tables: each cell in its column (cut to fit); the |---| row is not drawn.
    if (/^\s*\|.*\|\s*$/.test(content)) {
      if (/^\s*\|[\s:|-]+\|\s*$/.test(content)) continue
      const cells = content.trim().slice(1, -1).split('|').map((c) => stripInline(c.trim()))
      const column = (right - margin) / cells.length
      cells.forEach((cell, i) => {
        const x = Math.round(margin + i * column)
        const room = Math.max(1, Math.floor((column - body) / (body * CHAR_WIDTH.sans)))
        lines.push({ text: cell.slice(0, room), x, y, size: body, bold: false })
      })
      y += lineHeight(body, false)
      continue
    }

    if (content.trim() === '') {
      y += Math.round(body * 0.7)
      continue
    }
    place(stripInline(content), { x: margin, size: body, bold: false })
  }
  // A block still open where the page (or the file's start) ends.
  if (fence) boxes.push({ kind: 'code', x: margin, y: fence.top, width: right - margin, height: Math.min(y + pad, height) - fence.top })
  closeQuote()
  return { margin, lines, boxes }
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
