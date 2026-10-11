import { describe, expect, it } from 'vitest'
import { currentHeading, headingsOf } from './headings'

describe('headingsOf', () => {
  it('lists headings with their levels and lines', () => {
    expect(headingsOf('# Title\ntext\n## Part **one**\n### `code` bit ###')).toEqual([
      { level: 1, text: 'Title', line: 1 },
      { level: 2, text: 'Part one', line: 3 },
      { level: 3, text: 'code bit', line: 4 },
    ])
  })

  it('skips fenced code and lines that are not headings', () => {
    expect(headingsOf('```bash\n# a comment\n```\n#not a heading\n# Real')).toEqual([{ level: 1, text: 'Real', line: 5 }])
  })

  it('handles an unclosed fence', () => {
    expect(headingsOf('# A\n~~~\n# B')).toEqual([{ level: 1, text: 'A', line: 1 }])
  })
})

describe('currentHeading', () => {
  const hs = headingsOf('intro\n# A\ntext\n## B\ntext')
  it('is the last heading at or above the line', () => {
    expect(currentHeading(hs, 1)).toBe(-1)
    expect(currentHeading(hs, 3)).toBe(0)
    expect(currentHeading(hs, 5)).toBe(1)
  })
})
