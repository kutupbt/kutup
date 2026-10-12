import { describe, expect, it } from 'vitest'
import type { EntryView, VaultView } from '../vault/types'
import { securityReport } from './report'

function entry(id: string, title: string, password: string, extra: Partial<EntryView> = {}): EntryView {
  return {
    id,
    groupId: 'g',
    fields: [
      { key: 'Title', value: title, protected: false },
      { key: 'Password', value: password, protected: true },
    ],
    tags: [],
    icon: null,
    hasCustomIcon: false,
    customIcon: null,
    foregroundColor: null,
    backgroundColor: null,
    overrideUrl: '',
    qualityCheck: true,
    expires: false,
    expiry: null,
    created: null,
    modified: null,
    accessed: null,
    attachments: [],
    autoType: null,
    historyCount: 0,
    review: [],
    inRecycleBin: false,
    ...extra,
  }
}

function vault(entries: EntryView[]): VaultView {
  return {
    name: 'v',
    description: '',
    defaultUserName: '',
    rootGroupId: 'g',
    recycleBinId: null,
    recycleBinEnabled: true,
    historyMaxItems: 10,
    historyMaxSize: null,
    groups: [],
    entries,
    customIcons: [],
  }
}

describe('securityReport', () => {
  it('finds weak, reused and expired passwords, leaving the recycle bin out', () => {
    const strong = 'X7#kq9!vPz2@Lm4$Wn8^'
    const report = securityReport(
      vault([
        entry('1', 'Bank', strong),
        entry('2', 'Mail', strong),
        entry('3', 'Forum', 'abc123'),
        entry('4', 'Old', 'R5%tY7&uI9*oP1(aS3)d', { expires: true, expiry: '2020-01-01T00:00:00Z' }),
        entry('5', 'Gone', 'abc123', { inRecycleBin: true }),
        entry('6', 'Note', ''),
      ]),
      new Date('2026-10-12T00:00:00Z'),
    )
    expect(report.weak.map((e) => e.id)).toEqual(['3'])
    expect(report.reused.map((g) => g.map((e) => e.id))).toEqual([['1', '2']])
    expect(report.expired.map((e) => e.id)).toEqual(['4'])
    expect(report.checked).toBe(4)
  })

  it('reports nothing for a healthy vault', () => {
    const report = securityReport(vault([entry('1', 'A', 'X7#kq9!vPz2@Lm4$Wn8^')]))
    expect(report.weak).toEqual([])
    expect(report.reused).toEqual([])
    expect(report.expired).toEqual([])
  })
})
