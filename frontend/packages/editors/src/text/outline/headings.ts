// A Markdown note's headings, for its outline: ATX headings (`# …`) outside
// fenced code, with their inline marks left out.

export interface Heading {
  level: number
  text: string
  /** 1-based line number in the note. */
  line: number
}

/** Plain heading text: emphasis, code marks and link targets go. */
function plain(text: string): string {
  return text
    .replace(/\s+#+\s*$/, '') // closing hashes
    .replace(/!\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/(\*\*|__)(?=\S)(.+?)(?<=\S)\1/g, '$2')
    .replace(/(\*|_)(?=\S)(.+?)(?<=\S)\1/g, '$2')
    .replace(/`([^`]+)`/g, '$1')
    .trim()
}

export function headingsOf(text: string): Heading[] {
  const headings: Heading[] = []
  let fence: string | null = null
  text.split('\n').forEach((raw, i) => {
    const mark = /^\s{0,3}(`{3,}|~{3,})/.exec(raw)
    if (fence) {
      if (mark && mark[1][0] === fence[0] && mark[1].length >= fence.length) fence = null
      return
    }
    if (mark) {
      fence = mark[1]!
      return
    }
    const heading = /^\s{0,3}(#{1,6})\s+(.+)$/.exec(raw)
    if (heading) {
      const title = plain(heading[2])
      if (title) headings.push({ level: heading[1].length, text: title, line: i + 1 })
    }
  })
  return headings
}

/** The heading whose section holds `line` (the last one at or above it), or -1. */
export function currentHeading(headings: Heading[], line: number): number {
  let index = -1
  for (let i = 0; i < headings.length && headings[i].line <= line; i++) index = i
  return index
}
