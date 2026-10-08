// Keeps a chat timeline where it belongs: at the newest message while you
// are there, still while you read older ones (with a "jump to latest" when
// something arrives below), and steady when older messages load above.
import { useCallback, useLayoutEffect, useMemo, useRef, useState } from 'react'
import { ArrowDown } from 'lucide-react'

import { Button } from '@kutup/ui/components/button'
import { cn } from '@kutup/ui/lib/cn'

const LIVE_EDGE_THRESHOLD_PX = 56

interface ScrollSnapshot {
  atLiveEdge: boolean
  conversationKey: string | null
  itemKeys: string[]
  scrollHeight: number
  scrollTop: number
}

interface MessageScrollerProps {
  children: React.ReactNode
  className?: string
  conversationKey: string | null
  /** On opening, bring this element into view instead of the newest message
   *  (the unread marker, a search result). */
  anchorId?: string | null
  itemKeys: string[]
  jumpToLatestLabel: string
  timelineLabel: string
  /** Scrolled near the top: older messages can be read in. */
  onNearTop?: () => void
}

/** How close to the top older messages start loading. */
const NEAR_TOP_PX = 400

function isAtLiveEdge(element: HTMLElement): boolean {
  return element.scrollHeight - element.clientHeight - element.scrollTop <= LIVE_EDGE_THRESHOLD_PX
}

export function MessageScroller({
  children,
  className,
  conversationKey,
  anchorId,
  itemKeys,
  jumpToLatestLabel,
  timelineLabel,
  onNearTop,
}: MessageScrollerProps) {
  const viewportRef = useRef<HTMLDivElement>(null)
  const contentRef = useRef<HTMLDivElement>(null)
  const snapshotRef = useRef<ScrollSnapshot | null>(null)
  const [hasOffscreenArrival, setHasOffscreenArrival] = useState(false)
  const itemKeySignature = useMemo(() => itemKeys.join('\u001f'), [itemKeys])

  const captureSnapshot = useCallback(() => {
    const viewport = viewportRef.current
    if (!viewport) return
    snapshotRef.current = {
      atLiveEdge: isAtLiveEdge(viewport),
      conversationKey,
      itemKeys: [...itemKeys],
      scrollHeight: viewport.scrollHeight,
      scrollTop: viewport.scrollTop,
    }
    // The signature stands for the keys (a new array every render).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [conversationKey, itemKeySignature])

  useLayoutEffect(() => {
    const viewport = viewportRef.current
    if (!viewport) return

    const previous = snapshotRef.current
    if (!previous || previous.conversationKey !== conversationKey) {
      const anchor = anchorId ? document.getElementById(anchorId) : null
      if (anchor && viewport.contains(anchor)) anchor.scrollIntoView({ block: 'center' })
      else viewport.scrollTop = viewport.scrollHeight
      setHasOffscreenArrival(false)
      captureSnapshot()
      return
    }

    const previousFirstKey = previous.itemKeys[0]
    const previousLastKey = previous.itemKeys.at(-1)
    const firstPreviousIndex = previousFirstKey ? itemKeys.indexOf(previousFirstKey) : -1
    const lastPreviousIndex = previousLastKey ? itemKeys.lastIndexOf(previousLastKey) : -1
    const prepended = firstPreviousIndex > 0
    const appended = lastPreviousIndex >= 0 && lastPreviousIndex < itemKeys.length - 1

    if (prepended) {
      viewport.scrollTop = previous.scrollTop + (viewport.scrollHeight - previous.scrollHeight)
    } else if (previous.atLiveEdge) {
      viewport.scrollTop = viewport.scrollHeight
      setHasOffscreenArrival(false)
    } else if (appended) {
      setHasOffscreenArrival(true)
    }

    captureSnapshot()
    // Runs when the items change (their signature), not when the anchor
    // does: the anchor only matters on opening.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [captureSnapshot, conversationKey, itemKeySignature])

  useLayoutEffect(() => {
    const viewport = viewportRef.current
    const content = contentRef.current
    if (!viewport || !content || typeof ResizeObserver === 'undefined') return

    const observer = new ResizeObserver(() => {
      if (snapshotRef.current?.atLiveEdge) viewport.scrollTop = viewport.scrollHeight
      captureSnapshot()
    })
    observer.observe(content)
    return () => observer.disconnect()
  }, [captureSnapshot])

  const jumpToLatest = () => {
    const viewport = viewportRef.current
    if (!viewport) return
    viewport.scrollTo({
      top: viewport.scrollHeight,
      behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth',
    })
    setHasOffscreenArrival(false)
    captureSnapshot()
  }

  return (
    <div className="relative flex min-h-0 flex-1">
      <div
        ref={viewportRef}
        role="log"
        aria-label={timelineLabel}
        aria-live="off"
        className={cn('min-h-0 flex-1 overflow-y-auto', className)}
        data-testid="chat-message-scroller"
        onScroll={() => {
          const viewport = viewportRef.current
          if (viewport && isAtLiveEdge(viewport)) setHasOffscreenArrival(false)
          if (viewport && viewport.scrollTop < NEAR_TOP_PX) onNearTop?.()
          captureSnapshot()
        }}
      >
        <div ref={contentRef}>{children}</div>
      </div>
      {hasOffscreenArrival && (
        <Button
          type="button"
          size="sm"
          className="absolute bottom-4 left-1/2 z-10 -translate-x-1/2 gap-2 rounded-full shadow-lg"
          onClick={jumpToLatest}
        >
          <ArrowDown aria-hidden="true" />
          {jumpToLatestLabel}
        </Button>
      )}
    </div>
  )
}
