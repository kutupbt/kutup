// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import '../media/testI18n'
import type { ChatHistoryEntry } from '@kutup/chat-core/types'
import type { MessageView } from '../../state/views'

vi.mock('../../app/chatStore', () => ({
  useChat: () => ({ service: {} }),
  refreshChat: vi.fn(() => Promise.resolve(undefined)),
}))

const { DeliveryStatus } = await import('./MessageBubble')

afterEach(cleanup)

function view(entry: Partial<ChatHistoryEntry>): MessageView {
  return {
    entry: {
      id: 'm1',
      conversation: { kind: 'group', groupId: 'G'.repeat(43) },
      sender: 'aci:00000000-0000-4000-8000-00000000000e@a.test',
      direction: 'outgoing',
      timestampMs: Date.now(),
      delivered: false,
      deduplicated: false,
      ...entry,
    },
    receipt: null,
  } as unknown as MessageView
}

describe('a pairwise group message’s status', () => {
  it('is sending to the members our server hasn’t taken it for, then sent', () => {
    const { rerender } = render(<DeliveryStatus view={view({ waitingRecipients: 2 })} />)
    expect(screen.getByTestId('chat-receipt-sending')).toHaveAttribute('aria-label', 'Sending to 2 members')

    rerender(<DeliveryStatus view={view({ waitingRecipients: 0 })} />)
    expect(screen.queryByTestId('chat-receipt-sending')).toBeNull()
    expect(screen.getByTestId('chat-receipt-sent')).toBeVisible()
  })

  it('says who it never reached while the rest still wait', () => {
    render(<DeliveryStatus view={view({ waitingRecipients: 1, failedRecipients: 1 })} />)
    expect(screen.getByTestId('chat-receipt-partial')).toHaveAttribute('aria-label', 'Not delivered to 1 member')
  })
})
