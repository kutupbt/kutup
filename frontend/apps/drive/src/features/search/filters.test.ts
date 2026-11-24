import { describe, expect, it } from 'vitest'
import { activeFilters, filtersFromParams, modifiedSince, NO_FILTERS, passesFilters, withFilters, type FilterSubject } from './filters'

const now = new Date(2026, 10, 24, 15, 30)
const subject = (over: Partial<FilterSubject> = {}): FilterSubject => ({
  modifiedAt: new Date(2026, 10, 24, 9, 0).toISOString(),
  owned: true,
  createdByMe: true,
  sharedByMe: false,
  ...over,
})

describe('search filters', () => {
  it('round-trips through the URL and keeps the query', () => {
    const filters = { modified: 'week', place: 'shared', createdBy: 'others', sharedByMe: true } as const
    const params = withFilters(new URLSearchParams({ q: 'report' }), filters)
    expect(params.get('q')).toBe('report')
    expect(filtersFromParams(params)).toEqual(filters)
    expect(activeFilters(filters)).toBe(4)
    const cleared = withFilters(params, NO_FILTERS)
    expect(cleared.toString()).toBe('q=report')
  })

  it('ignores values it does not know', () => {
    expect(filtersFromParams(new URLSearchParams('modified=decade&in=elsewhere&by=x&shared=1'))).toEqual(NO_FILTERS)
  })

  it('takes today from local midnight and the rest as rolling days', () => {
    expect(modifiedSince('today', now)).toEqual(new Date(2026, 10, 24))
    expect(now.getTime() - modifiedSince('week', now).getTime()).toBe(7 * 86_400_000)
    expect(now.getTime() - modifiedSince('year', now).getTime()).toBe(365 * 86_400_000)
  })

  it('lets through what every filter on allows', () => {
    expect(passesFilters(subject(), NO_FILTERS, now)).toBe(true)
    const yesterday = subject({ modifiedAt: new Date(2026, 10, 23, 23, 0).toISOString() })
    expect(passesFilters(yesterday, { ...NO_FILTERS, modified: 'today' }, now)).toBe(false)
    expect(passesFilters(yesterday, { ...NO_FILTERS, modified: 'week' }, now)).toBe(true)
    expect(passesFilters(subject({ owned: false }), { ...NO_FILTERS, place: 'mine' }, now)).toBe(false)
    expect(passesFilters(subject({ owned: false }), { ...NO_FILTERS, place: 'shared' }, now)).toBe(true)
    expect(passesFilters(subject(), { ...NO_FILTERS, createdBy: 'others' }, now)).toBe(false)
    expect(passesFilters(subject(), { ...NO_FILTERS, sharedByMe: true }, now)).toBe(false)
    expect(passesFilters(subject({ sharedByMe: true }), { ...NO_FILTERS, sharedByMe: true, createdBy: 'me' }, now)).toBe(true)
  })
})
