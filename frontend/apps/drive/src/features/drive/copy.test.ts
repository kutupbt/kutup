import { describe, expect, it } from 'vitest'
import { copyName, isWithin } from './copy'
import type { FolderIndex } from './folders'
import type { Folder } from './model'

describe('copyName', () => {
  it('keeps a free name', () => {
    expect(copyName('report.pdf', ['other.pdf'])).toBe('report.pdf')
  })

  it('numbers a clash before the extension, case-insensitively', () => {
    expect(copyName('Report.pdf', ['report.PDF'])).toBe('Report (1).pdf')
    expect(copyName('report.pdf', ['report.pdf', 'report (1).pdf'])).toBe('report (2).pdf')
  })

  it('numbers names without an extension, and dotfiles, at the end', () => {
    expect(copyName('Projects', ['projects'])).toBe('Projects (1)')
    expect(copyName('.env', ['.env'])).toBe('.env (1)')
  })
})

describe('isWithin', () => {
  const folder = (id: string, parentId: string | null) => ({ id, parentId, source: 'owned' }) as Folder
  const all = [folder('root', null), folder('a', 'root'), folder('b', 'a'), folder('c', 'root')]
  const index = { byId: new Map(all.map((f) => [f.id, f])) } as FolderIndex

  it('finds a folder itself and its descendants', () => {
    expect(isWithin(index, all[1], all[1])).toBe(true)
    expect(isWithin(index, all[2], all[1])).toBe(true)
  })

  it('does not treat parents or siblings as inside', () => {
    expect(isWithin(index, all[0], all[1])).toBe(false)
    expect(isWithin(index, all[3], all[1])).toBe(false)
  })
})
