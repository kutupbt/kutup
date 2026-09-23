import { describe, expect, it } from 'vitest'
import { intersects, rectBetween } from './useMarquee'

describe('selection box geometry', () => {
  it('normalises a box dragged in any direction', () => {
    expect(rectBetween(50, 60, 10, 20)).toEqual({ left: 10, top: 20, width: 40, height: 40 })
  })

  it('selects what the box touches, not what it only borders', () => {
    const box = rectBetween(0, 0, 100, 100)
    expect(intersects(box, { left: 90, top: 90, width: 50, height: 50 })).toBe(true)
    expect(intersects(box, { left: 100, top: 0, width: 50, height: 50 })).toBe(false)
    expect(intersects(box, { left: 200, top: 200, width: 10, height: 10 })).toBe(false)
  })
})
