import { describe, expect, it } from 'vitest'
import { EMPTY_SEARCH, isSearching, listCriteria, searchFromParams, searchToParams } from './search'

describe('advanced search', () => {
  it('goes to the address bar and back', () => {
    const search = { ...EMPTY_SEARCH, q: 'fatura', from: 'ayse', to: 'ekip', since: '2026-10-01', until: '2026-10-12', address: 'Liste@Kutup.dev', attachments: true }
    const params = searchToParams(search)
    expect(params.toString()).toBe('q=fatura&from=ayse&to=ekip&since=2026-10-01&until=2026-10-12&address=Liste%40Kutup.dev&filter=attachments')
    expect(searchFromParams(params)).toEqual({ ...search, address: 'liste@kutup.dev' })
  })

  it('drops days that are not days, and knows a search from a filter', () => {
    const read = searchFromParams(new URLSearchParams('since=yesterday&filter=attachments'))
    expect(read.since).toBe('')
    expect(isSearching(read)).toBe(false)
    expect(isSearching({ ...EMPTY_SEARCH, until: '2026-01-01' })).toBe(true)
  })

  it('includes the end day, in the reader’s time zone', () => {
    const criteria = listCriteria({ ...EMPTY_SEARCH, since: '2026-10-01', until: '2026-10-01' })
    expect(new Date(criteria.since!).getTime()).toBe(new Date(2026, 9, 1).getTime())
    expect(new Date(criteria.until!).getTime()).toBe(new Date(2026, 9, 2).getTime())
    expect(listCriteria(EMPTY_SEARCH)).toEqual({})
  })
})
