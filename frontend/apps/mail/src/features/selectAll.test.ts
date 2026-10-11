import { describe, expect, it } from 'vitest'
import { canSelectAll } from './selectAll'

describe('canSelectAll', () => {
  const base = { checked: 50, pageSize: 50, folder: 'inbox' as const, own: false, q: '', filtered: false }

  it('offers select all once a whole page is checked, as Proton', () => {
    expect(canSelectAll(base)).toBe(true)
    expect(canSelectAll({ ...base, checked: 49 })).toBe(false)
  })

  it('leaves out All mail, a search and a filter', () => {
    expect(canSelectAll({ ...base, folder: 'all' })).toBe(false)
    // Your own folders and labels list as All mail does, but are places of their own.
    expect(canSelectAll({ ...base, folder: 'all', own: true })).toBe(true)
    expect(canSelectAll({ ...base, q: 'fatura' })).toBe(false)
    expect(canSelectAll({ ...base, filtered: true })).toBe(false)
  })
})
