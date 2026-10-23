import type { PointerEvent as ReactPointerEvent } from 'react'
import { LONG_PRESS_MS, Press } from './gridInteraction'

export interface Point {
  x: number
  y: number
}

export interface PressHandlers {
  /** The press became a drag, or a drag moved: where the pointer is. */
  drag: (point: Point) => void
  /** A drag ended where it was last told. */
  drop: () => void
  /** The press ended without a drag (or, for a touch, a scroll). */
  click: () => void
  /** Escape, a scroll taking over, or the pointer lost. */
  cancel: () => void
  /** A touch rested long enough: it drags from here (for feedback). */
  armed?: () => void
}

/** Whether a touch drag holds the page still (read by `holdTouches`' listener). */
let holding = false
/** Presses being followed now. */
let active = 0

/** Whether a press is being followed (the page's shortcuts wait for it to end). */
export function pressActive(): boolean {
  return active > 0
}

/**
 * Keeps an armed or dragging touch from scrolling `element`: a listener in
 * place before any touch starts, as browsers decide then whether one can
 * stop the scroll. Returns its removal.
 */
export function holdTouches(element: HTMLElement): () => void {
  const hold = (e: TouchEvent) => {
    if (holding) e.preventDefault()
  }
  element.addEventListener('touchmove', hold, { passive: false })
  return () => element.removeEventListener('touchmove', hold)
}

/** Auto-scroll: within this many pixels of the scroller's edge, this many per frame (Proton's 7 and 5, a touch more generous). */
const EDGE_PX = 24
const SCROLL_STEP_PX = 8

/**
 * Follows one press from pointerdown to its end: a mouse drags past the
 * threshold, a touch after a long press (so a swipe still scrolls the
 * grid); Escape cancels a drag; near the scroller's top or bottom edge the
 * grid scrolls on its own; the click a drag would end with is swallowed.
 */
export function follow(event: ReactPointerEvent, handlers: PressHandlers, scroller: HTMLElement | null): void {
  if (event.pointerType !== 'touch' && event.button !== 0) return
  // A pen drags as a mouse does (it doesn't scroll the page by moving); only
  // a finger needs the long press.
  const kind = event.pointerType === 'touch' ? 'touch' : 'mouse'
  const press = new Press(kind, event.clientX, event.clientY, performance.now())
  let last: Point = { x: event.clientX, y: event.clientY }
  let frame = 0
  let timer = 0
  const id = event.pointerId

  const scroll = () => {
    frame = 0
    if (press.state !== 'dragging' || !scroller) return
    const rect = scroller.getBoundingClientRect()
    const by = last.y < rect.top + EDGE_PX ? -SCROLL_STEP_PX : last.y > rect.bottom - EDGE_PX ? SCROLL_STEP_PX : 0
    if (by !== 0) {
      const before = scroller.scrollTop
      scroller.scrollTop += by
      if (scroller.scrollTop !== before) handlers.drag(last)
    }
    frame = requestAnimationFrame(scroll)
  }
  let ended = false
  const end = () => {
    if (!ended) {
      ended = true
      active -= 1
    }
    window.removeEventListener('pointermove', move, true)
    window.removeEventListener('pointerup', up, true)
    window.removeEventListener('pointercancel', lost, true)
    window.removeEventListener('keydown', key, true)
    holding = false
    window.clearTimeout(timer)
    if (frame) cancelAnimationFrame(frame)
  }
  const move = (e: PointerEvent) => {
    if (e.pointerId !== id) return
    last = { x: e.clientX, y: e.clientY }
    const before = press.state
    const now = press.move(e.clientX, e.clientY, performance.now())
    if (now === 'scrolling') {
      end()
      handlers.cancel()
      return
    }
    if (now === 'dragging') {
      e.preventDefault()
      if (before !== 'dragging' && !frame) frame = requestAnimationFrame(scroll)
      handlers.drag(last)
    }
  }
  const up = (e: PointerEvent) => {
    if (e.pointerId !== id) return
    end()
    if (press.state === 'dragging') {
      // The click the browser sends after this mouseup isn't one.
      const swallow = (c: MouseEvent) => {
        c.stopPropagation()
        c.preventDefault()
      }
      window.addEventListener('click', swallow, { capture: true, once: true })
      window.setTimeout(() => window.removeEventListener('click', swallow, true), 0)
      handlers.drop()
    } else if (press.isClick()) handlers.click()
    else handlers.cancel()
  }
  const lost = (e: PointerEvent) => {
    if (e.pointerId !== id) return
    end()
    handlers.cancel()
  }
  const key = (e: KeyboardEvent) => {
    if (e.key !== 'Escape') return
    e.preventDefault()
    e.stopPropagation()
    end()
    handlers.cancel()
  }
  active += 1
  window.addEventListener('pointermove', move, true)
  window.addEventListener('pointerup', up, true)
  window.addEventListener('pointercancel', lost, true)
  window.addEventListener('keydown', key, true)
  if (kind === 'touch') {
    timer = window.setTimeout(() => {
      press.tick(performance.now())
      if (press.state === 'armed') {
        // Once armed, the page doesn't scroll under the finger.
        holding = true
        navigator.vibrate?.(10)
        handlers.armed?.()
      }
    }, LONG_PRESS_MS)
  }
}
