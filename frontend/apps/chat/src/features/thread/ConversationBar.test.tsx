// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import '../media/testI18n'

const INVITER = 'aci:00000000-0000-4000-8000-81b637d8fcd2@a.test'
const service = {
  acceptChatGroupInvite: vi.fn(() => Promise.resolve({ kind: 'current', revision: 4, keyConfirmed: true })),
  declineChatGroupInvite: vi.fn((_groupId: string) => Promise.resolve(undefined)),
  blockContact: vi.fn(() => Promise.resolve(undefined)),
}
const invited = (groupId: string, inviter: string) => ({ groupId, title: 'Team', status: 'invited', memberCount: 0, forkSuspected: false, inviter })
const chat = {
  service,
  snapshot: {
    profiles: [{ peer: INVITER, displayName: 'Bob' }],
    // Another invitation from the same person, and one from someone else.
    chatGroups: [invited('G'.repeat(43), INVITER), invited('H'.repeat(43), INVITER), invited('K'.repeat(43), 'aci:00000000-0000-4000-8000-0000000000c3@a.test')],
  },
  self: { key: 'aci:00000000-0000-4000-8000-00000000000e@a.test' },
}
vi.mock('../../app/chatStore', () => ({
  useChat: () => chat,
  refreshChat: vi.fn(() => Promise.resolve(undefined)),
}))

const { ConversationBar } = await import('./ConversationBar')

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

/** The text as read, without the direction isolates around someone else's words. */
const read = (text: string) => (_: string, element: Element | null) =>
  element?.tagName === 'SPAN' && (element.textContent ?? '').replace(/[\u2068\u2069]/g, '') === text

function invitation(request: boolean) {
  return {
    readOnly: 'invitation',
    title: 'Team',
    peer: null,
    chatGroup: { groupId: 'G'.repeat(43), title: 'Team', status: 'invited', memberCount: 0, forkSuspected: false, inviter: INVITER },
    groupInviter: INVITER,
    groupInviteRequest: request,
    readiness: { pending: [], refused: [], blocksSending: false },
  } as never
}

describe('an invitation to a pairwise group', () => {
  it('names who invited, and joins', async () => {
    render(<MemoryRouter><ConversationBar model={invitation(false)} /></MemoryRouter>)
    expect(screen.getByText(read('Bob invited you to “Team”'))).toBeVisible()
    // Their words can't reorder the sentence: each is its own isolated run.
    expect(screen.getByText(read('Bob invited you to “Team”')).textContent).toBe('\u2068Bob\u2069 invited you to “\u2068Team\u2069”')
    expect(screen.queryByRole('button', { name: 'Block' })).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Join group' }))
    await waitFor(() => expect(service.acceptChatGroupInvite).toHaveBeenCalledWith('G'.repeat(43)))
  })

  it('from a stranger, is a request that can be declined with a block', async () => {
    render(<MemoryRouter><ConversationBar model={invitation(true)} /></MemoryRouter>)
    expect(screen.getByText(/isn't in your contacts/)).toBeVisible()
    fireEvent.click(screen.getByRole('button', { name: 'Block' }))
    await waitFor(() => expect(service.declineChatGroupInvite).toHaveBeenCalledTimes(2))
    // Blocked first, then every invitation of theirs declined; not others'.
    expect(service.blockContact).toHaveBeenCalledWith(INVITER)
    expect(service.blockContact.mock.invocationCallOrder[0]).toBeLessThan(service.declineChatGroupInvite.mock.invocationCallOrder[0])
    expect(service.declineChatGroupInvite.mock.calls.map(([id]) => id)).toEqual(['G'.repeat(43), 'H'.repeat(43)])
  })

  it('declines just this one', async () => {
    render(<MemoryRouter><ConversationBar model={invitation(true)} /></MemoryRouter>)
    fireEvent.click(screen.getByRole('button', { name: 'Decline' }))
    await waitFor(() => expect(service.declineChatGroupInvite).toHaveBeenCalledWith('G'.repeat(43)))
    expect(service.declineChatGroupInvite).toHaveBeenCalledTimes(1)
    expect(service.blockContact).not.toHaveBeenCalled()
  })
})
