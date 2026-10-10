import { describe, expect, it } from 'vitest'
import { filterProblems, type FilterDraft } from './filters'

describe('filterProblems', () => {
  const ok: FilterDraft = {
    name: 'Faturalar',
    match: 'all',
    conditions: [{ field: 'subject', op: 'contains', negate: false, value: 'fatura' }],
    actions: { folder: 'archive' },
  }

  it('accepts a complete filter', () => {
    expect(filterProblems(ok)).toEqual([])
    // "Has attachments" needs no value.
    expect(filterProblems({ ...ok, conditions: [{ field: 'attachments', op: 'contains', negate: true, value: '' }] })).toEqual([])
  })

  it('names what is missing', () => {
    expect(filterProblems({ ...ok, name: '  ' })).toEqual(['name'])
    expect(filterProblems({ ...ok, conditions: [] })).toEqual(['conditions'])
    expect(filterProblems({ ...ok, conditions: [{ ...ok.conditions[0], value: ' ' }] })).toEqual(['conditions'])
    expect(filterProblems({ ...ok, actions: {} })).toEqual(['actions'])
    expect(filterProblems({ ...ok, actions: { labels: [] } })).toEqual(['actions'])
  })
})
