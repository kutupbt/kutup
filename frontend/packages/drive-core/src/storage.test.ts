import { describe, expect, it } from 'vitest'
import { largeFiles, storageLevel, usageCategories, versionsOlderThan, type OwnFile, type StorageUsage } from './storage'

const usage: StorageUsage = {
  quotaBytes: 1000,
  usedBytes: 600,
  reservedBytes: 10,
  drive: { filesBytes: 300, filesCount: 3, trashBytes: 50, trashCount: 1, versionsBytes: 40, thumbnailsBytes: 5, assetsBytes: 5 },
  chat: { mediaBytes: 120, historyBytes: 70, historyMediaBytes: 10 },
}

describe('usageCategories', () => {
  it('lists what fills the pool largest first and leaves out what is empty', () => {
    const ids = usageCategories({ ...usage, drive: { ...usage.drive, versionsBytes: 0 } }).map((c) => c.id)
    expect(ids).toEqual(['files', 'chatMedia', 'chatHistory', 'trash', 'previews', 'reserved'])
  })

  it('shares the charged file bytes out among kinds so they still add up', () => {
    const kinds = new Map([
      ['image', { bytes: 200, count: 2 }],
      ['document', { bytes: 100, count: 1 }],
      ['video', { bytes: 1, count: 1 }],
    ] as const)
    const categories = usageCategories(usage, new Map(kinds))
    const fileParts = categories.filter((c) => ['image', 'document', 'video'].includes(c.id))
    expect(fileParts.reduce((total, c) => total + c.bytes, 0)).toBe(300)
    expect(categories[0]).toMatchObject({ id: 'image', count: 2, color: 'var(--kind-image)' })
  })
})

describe('storageLevel', () => {
  it('warns from 80 per cent, counting uploads in flight, and is in danger when full', () => {
    expect(storageLevel({ quotaBytes: 100, usedBytes: 79, reservedBytes: 0 })).toBe('ok')
    expect(storageLevel({ quotaBytes: 100, usedBytes: 70, reservedBytes: 10 })).toBe('warning')
    expect(storageLevel({ quotaBytes: 100, usedBytes: 100, reservedBytes: 0 })).toBe('danger')
  })
})

describe('largeFiles', () => {
  it('keeps files of 10 MB and up, largest first', () => {
    const file = (id: string, size: number) => ({ folder: {}, file: { id, size } }) as unknown as OwnFile
    const result = largeFiles([file('a', 10_485_759), file('b', 20_000_000), file('c', 10_485_760)])
    expect(result.map((f) => f.file.id)).toEqual(['b', 'c'])
  })
})

describe('versionsOlderThan', () => {
  it('counts versions at least that old, and kept-forever ones only when asked', () => {
    const ages = [
      { ageDays: 3, keepForever: false, bytes: 10, count: 1 },
      { ageDays: 30, keepForever: false, bytes: 20, count: 2 },
      { ageDays: 90, keepForever: true, bytes: 40, count: 1 },
    ]
    expect(versionsOlderThan(ages, 30, false)).toEqual({ bytes: 20, count: 2 })
    expect(versionsOlderThan(ages, 30, true)).toEqual({ bytes: 60, count: 3 })
    expect(versionsOlderThan(ages, 1, false)).toEqual({ bytes: 30, count: 3 })
  })
})
