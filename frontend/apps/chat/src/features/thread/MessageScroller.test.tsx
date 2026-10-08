// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

import { MessageScroller } from './MessageScroller'

function renderScroller(itemKeys: string[], conversationKey = 'direct:alice') {
  return render(
    <MessageScroller
      conversationKey={conversationKey}
      itemKeys={itemKeys}
      timelineLabel="Conversation timeline"
      jumpToLatestLabel="Jump to latest"
    >
      {itemKeys.map((key) => <div key={key}>{key}</div>)}
    </MessageScroller>,
  )
}

/** Gives the element a size and a spied `scrollTo`, which it returns. */
function installGeometry(element: HTMLElement, geometry: { height: number; client: number }) {
  Object.defineProperty(element, 'scrollHeight', { configurable: true, get: () => geometry.height })
  Object.defineProperty(element, 'clientHeight', { configurable: true, get: () => geometry.client })
  const scrollTo = vi.fn(({ top }: ScrollToOptions) => {
    if (typeof top === 'number') element.scrollTop = top
    fireEvent.scroll(element)
  })
  Object.defineProperty(element, 'scrollTo', { configurable: true, value: scrollTo })
  return scrollTo
}

describe('MessageScroller compatibility spike', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('preserves the visible position when protected history is prepended', () => {
    const geometry = { height: 1_000, client: 400 }
    const view = renderScroller(['outgoing:1', 'incoming:2'])
    const scroller = screen.getByRole('log', { name: 'Conversation timeline' })
    installGeometry(scroller, geometry)
    scroller.scrollTop = 240
    fireEvent.scroll(scroller)

    geometry.height = 1_240
    view.rerender(
      <MessageScroller
        conversationKey="direct:alice"
        itemKeys={['incoming:0', 'outgoing:1', 'incoming:2']}
        timelineLabel="Conversation timeline"
        jumpToLatestLabel="Jump to latest"
      >
        <div>history</div>
      </MessageScroller>,
    )

    expect(scroller.scrollTop).toBe(480)
    expect(screen.queryByRole('button', { name: 'Jump to latest' })).not.toBeInTheDocument()
  })

  it('does not move an older reader for arrivals and exposes a jump action', () => {
    const geometry = { height: 1_000, client: 400 }
    const view = renderScroller(['outgoing:1', 'incoming:2'])
    const scroller = screen.getByTestId('chat-message-scroller')
    const scrollTo = installGeometry(scroller, geometry)
    scroller.scrollTop = 100
    fireEvent.scroll(scroller)

    geometry.height = 1_120
    view.rerender(
      <MessageScroller
        conversationKey="direct:alice"
        itemKeys={['outgoing:1', 'incoming:2', 'incoming:3']}
        timelineLabel="Conversation timeline"
        jumpToLatestLabel="Jump to latest"
      >
        <div>new arrival</div>
      </MessageScroller>,
    )

    expect(scroller.scrollTop).toBe(100)
    fireEvent.click(screen.getByRole('button', { name: 'Jump to latest' }))
    expect(scrollTo).toHaveBeenCalledWith(expect.objectContaining({ top: 1_120 }))
  })

  it('follows arrivals at the live edge and opens a new conversation at its latest item', () => {
    const geometry = { height: 1_000, client: 400 }
    const view = renderScroller(['outgoing:1'])
    const scroller = screen.getByTestId('chat-message-scroller')
    installGeometry(scroller, geometry)
    scroller.scrollTop = 600
    fireEvent.scroll(scroller)

    geometry.height = 1_100
    view.rerender(
      <MessageScroller
        conversationKey="direct:alice"
        itemKeys={['outgoing:1', 'incoming:2']}
        timelineLabel="Conversation timeline"
        jumpToLatestLabel="Jump to latest"
      >
        <div>latest</div>
      </MessageScroller>,
    )
    expect(scroller.scrollTop).toBe(1_100)

    geometry.height = 700
    view.rerender(
      <MessageScroller
        conversationKey="direct:bob"
        itemKeys={['incoming:9']}
        timelineLabel="Conversation timeline"
        jumpToLatestLabel="Jump to latest"
      >
        <div>other conversation</div>
      </MessageScroller>,
    )
    expect(scroller.scrollTop).toBe(700)
  })

  it('follows late media sizing only for a reader who remained at the live edge', () => {
    let notifyResize: () => void = () => undefined
    class ResizeObserverStub {
      constructor(callback: ResizeObserverCallback) {
        notifyResize = () => callback([], this)
      }
      observe() {}
      disconnect() {}
      unobserve() {}
    }
    vi.stubGlobal('ResizeObserver', ResizeObserverStub)

    const geometry = { height: 1_000, client: 400 }
    renderScroller(['incoming:image', 'outgoing:voice'])
    const scroller = screen.getByTestId('chat-message-scroller')
    installGeometry(scroller, geometry)
    scroller.scrollTop = 600
    fireEvent.scroll(scroller)

    geometry.height = 1_180
    notifyResize()
    expect(scroller.scrollTop).toBe(1_180)

    scroller.scrollTop = 200
    fireEvent.scroll(scroller)
    geometry.height = 1_300
    notifyResize()
    expect(scroller.scrollTop).toBe(200)
  })

  it('says when the reader is back at the newest messages', () => {
    const onLiveEdge = vi.fn()
    render(
      <MessageScroller
        conversationKey="direct:alice"
        itemKeys={['a', 'b']}
        timelineLabel="Conversation timeline"
        jumpToLatestLabel="Jump to latest"
        onLiveEdge={onLiveEdge}
      >
        <div>a</div>
      </MessageScroller>,
    )
    const scroller = screen.getByRole('log', { name: 'Conversation timeline' })
    installGeometry(scroller, { height: 1_000, client: 400 })
    scroller.scrollTop = 100
    fireEvent.scroll(scroller)
    expect(onLiveEdge).not.toHaveBeenCalled()
    scroller.scrollTop = 600
    fireEvent.scroll(scroller)
    expect(onLiveEdge).toHaveBeenCalledTimes(1)
  })
})
