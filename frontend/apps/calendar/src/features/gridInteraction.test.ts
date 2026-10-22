import { describe, expect, it } from 'vitest'
import { clickSpan, createSpan, localAt, LONG_PRESS_MS, Press, resizeEnd, shiftLocal, snap } from './gridInteraction'

describe('snapping and spans, as Proton’s time grid', () => {
  it('snaps down to half hours within the day', () => {
    expect(snap(0)).toBe(0)
    expect(snap(29)).toBe(0)
    expect(snap(30)).toBe(30)
    expect(snap(10 * 60 + 47)).toBe(10 * 60 + 30)
    expect(snap(-5)).toBe(0)
    expect(snap(24 * 60 + 10)).toBe(23 * 60 + 30)
  })

  it('makes a span downwards, upwards, and at least one slot', () => {
    expect(createSpan(600, 600)).toEqual({ start: 600, end: 630 })
    expect(createSpan(600, 690)).toEqual({ start: 600, end: 720 })
    expect(createSpan(600, 510)).toEqual({ start: 510, end: 600 })
    expect(createSpan(1410, 1410)).toEqual({ start: 1410, end: 1440 })
  })

  it('makes a click’s event of the default length, and resizes from the start on', () => {
    expect(clickSpan(600)).toEqual({ start: 600, end: 630 })
    expect(clickSpan(1430 - 20)).toEqual({ start: 1410, end: 1440 })
    expect(resizeEnd(600, 690)).toBe(720)
    expect(resizeEnd(600, 300)).toBe(630)
    expect(resizeEnd(600, 1430)).toBe(1440)
  })

  it('moves local times by days and minutes, across months and midnight', () => {
    expect(shiftLocal('2026-10-31T23:30:00', 0, 60)).toBe('2026-11-01T00:30:00')
    expect(shiftLocal('2026-10-29T10:10:00', 1, 30)).toBe('2026-10-30T10:40:00')
    expect(shiftLocal('2026-03-01T00:00:00', -1, 0)).toBe('2026-02-28T00:00:00')
    expect(localAt('2026-10-29', 24 * 60)).toBe('2026-10-30T00:00:00')
  })
})

describe('a press: click, drag or scroll', () => {
  it('drags with a mouse past 20 px, and stays a click below', () => {
    const press = new Press('mouse', 100, 100, 0)
    expect(press.move(100, 115, 10)).toBe('pressed')
    expect(press.isClick()).toBe(true)
    expect(press.move(100, 125, 20)).toBe('dragging')
    expect(press.isClick()).toBe(false)
  })

  it('scrolls when a touch moves before resting, drags after a long press', () => {
    const swipe = new Press('touch', 100, 100, 0)
    expect(swipe.move(100, 140, 50)).toBe('scrolling')
    expect(swipe.isClick()).toBe(false)
    const hold = new Press('touch', 100, 100, 0)
    hold.tick(LONG_PRESS_MS)
    expect(hold.state).toBe('armed')
    expect(hold.move(100, 103, LONG_PRESS_MS + 10)).toBe('dragging')
    // A rest that never moved is still a tap.
    const tap = new Press('touch', 100, 100, 0)
    tap.tick(LONG_PRESS_MS + 100)
    expect(tap.isClick()).toBe(true)
  })
})
