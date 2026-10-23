import { describe, expect, it } from 'vitest'
import { emptySelection, inOrder, keepShown, selectAll, selectRange, toggle } from './selection'

const order = ['a', 'b', 'c', 'd', 'e']
const ids = (s: { ids: ReadonlySet<string> }) => [...s.ids].sort()

describe('entry selection', () => {
  it('toggles one, which becomes the anchor', () => {
    const one = toggle(emptySelection, 'b')
    expect(ids(one)).toEqual(['b'])
    expect(one.anchor).toBe('b')
    const none = toggle(one, 'b')
    expect(ids(none)).toEqual([])
    expect(none.anchor).toBe('b')
  })

  it('takes a range from the anchor, either way, adding to what is selected', () => {
    const start = toggle(toggle(emptySelection, 'a'), 'd')
    expect(ids(selectRange(start, order, 'b'))).toEqual(['a', 'b', 'c', 'd'])
    expect(ids(selectRange(start, order, 'e'))).toEqual(['a', 'd', 'e'])
    expect(selectRange(start, order, 'e').anchor).toBe('d')
    // No anchor shown: just that one.
    expect(ids(selectRange(emptySelection, order, 'c'))).toEqual(['c'])
    // Not in the list: nothing changes.
    expect(selectRange(start, order, 'z')).toBe(start)
  })

  it('selects all shown, and keeps only what is still shown', () => {
    const all = selectAll(order)
    expect(ids(all)).toEqual(order)
    const left = keepShown(all, ['a', 'c'])
    expect(ids(left)).toEqual(['a', 'c'])
    expect(left.anchor).toBe('a')
    expect(keepShown(left, ['a', 'c'])).toBe(left)
    expect(keepShown(toggle(emptySelection, 'b'), ['a']).anchor).toBeNull()
  })

  it('gives the selected ids in the list order', () => {
    expect(inOrder(toggle(toggle(emptySelection, 'd'), 'a'), order)).toEqual(['a', 'd'])
  })
})
