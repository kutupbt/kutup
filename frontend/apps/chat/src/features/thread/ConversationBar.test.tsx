// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import '../media/testI18n'

const INVITER = 'aci:00000000-0000-4000-8000-81b637d8fcd2@a.test'
const service = {
  acceptChatGroupInvite: vi.fn(() => Promise.resolve({ kind: 'current', revision: 4, keyConfirmed: true })),
  declineChatGroupInvite: vi.fn(() => Promise.resolve(undefined)),
  blockContact: vi.fn(() => Promise.resolve(undefined)),
}
const chat = {
  service,
  snapshot: { profiles: [{ peer: INVITER, displayName: 'Bob' }] },
  self: { key: 'aci:00000000-0000-4000-8000-00000000000e@a.test' },
}
vi.mock('../../app/chatStore', () => ({
  useChat: () => chat,
  refreshChat: vi.fn(() => Promise.resolve(undefined)),
}))

const { ConversationBar } = await import('./ConversationBar')

afterEach(cleanup)

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
    expect(screen.getByText('Bob invited you to “Team”')).toBeVisible()
    expect(screen.queryByRole('button', { name: 'Block' })).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Join group' }))
    await waitFor(() => expect(service.acceptChatGroupInvite).toHaveBeenCalledWith('G'.repeat(43)))
  })

  it('from a stranger, is a request that can be declined with a block', async () => {
    render(<MemoryRouter><ConversationBar model={invitation(true)} /></MemoryRouter>)
    expect(screen.getByText(/isn't in your contacts/)).toBeVisible()
    fireEvent.click(screen.getByRole('button', { name: 'Block' }))
    await waitFor(() => expect(service.blockContact).toHaveBeenCalledWith(INVITER))
    expect(service.declineChatGroupInvite).toHaveBeenCalledWith('G'.repeat(43))
  })
})
