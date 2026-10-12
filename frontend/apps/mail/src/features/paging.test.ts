import { describe, expect, it } from 'vitest'
import { pageCount, pageFromParams, pageNumbers } from './paging'

describe('paging', () => {
  it('counts pages, at least one', () => {
    expect(pageCount(0, 50)).toBe(1)
    expect(pageCount(50, 50)).toBe(1)
    expect(pageCount(51, 50)).toBe(2)
  })

  it('shows the first, the last and the pages around, as Proton', () => {
    expect(pageNumbers(1, 1)).toEqual([1])
    expect(pageNumbers(1, 2)).toEqual([1, 2])
    expect(pageNumbers(1, 10)).toEqual([1, 2, 3, 'gap', 10])
    expect(pageNumbers(10, 10)).toEqual([1, 'gap', 8, 9, 10])
    expect(pageNumbers(5, 10)).toEqual([1, 'gap', 4, 5, 6, 'gap', 10])
    expect(pageNumbers(2, 10)).toEqual([1, 2, 3, 'gap', 10])
    expect(pageNumbers(3, 4)).toEqual([1, 2, 3, 4])
  })

  it('reads the page from the address bar', () => {
    expect(pageFromParams(new URLSearchParams('page=3'))).toBe(3)
    expect(pageFromParams(new URLSearchParams(''))).toBe(1)
    expect(pageFromParams(new URLSearchParams('page=0'))).toBe(1)
    expect(pageFromParams(new URLSearchParams('page=x'))).toBe(1)
  })
})
