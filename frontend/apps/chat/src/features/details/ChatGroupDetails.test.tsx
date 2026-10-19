// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import '../media/testI18n'
import type { ChatGroupMember, ChatGroupSummary } from '@kutup/chat-core/types'

const SELF = 'aci:00000000-0000-4000-8000-00000000000e@a.test'
const BOB = 'aci:00000000-0000-4000-8000-0000000000b2@a.test'
const CAROL = 'aci:00000000-0000-4000-8000-0000000000c3@a.test'

let members: Promise<ChatGroupMember[]>
const service = {
  chatGroupMembers: vi.fn(() => members),
  removeChatGroupMember: vi.fn(() => Promise.resolve(undefined)),
  setChatGroupAdmin: vi.fn(() => Promise.resolve(undefined)),
  leaveChatGroup: vi.fn(() => Promise.resolve(undefined)),
}
const chat = {
  service,
  snapshot: {
    profiles: [
      { peer: BOB, displayName: 'Bob' },
      { peer: CAROL, displayName: 'Carol' },
    ],
    contacts: [],
  },
  self: { key: SELF },
}
vi.mock('../../app/chatStore', () => ({
  useChat: () => chat,
  refreshChat: vi.fn(() => Promise.resolve(undefined)),
}))

const { ChatGroupDetails } = await import('./ChatGroupDetails')

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

const member = (account: string | null, administrator: boolean, pseudonym: string): ChatGroupMember => ({
  pseudonym,
  administrator,
  joinedAtRevision: 1,
  account,
})

function group(access: ChatGroupSummary['access'] = { attributes: 'member', members: 'member', addFromInviteLink: 'unsatisfiable' }): ChatGroupSummary {
  return { groupId: 'G'.repeat(43), title: 'Team', status: 'member', revision: 3, memberCount: 3, forkSuspected: false, access }
}

describe('a pairwise group’s members', () => {
  it('asks before removing someone, and before taking away an admin; making one is one step', async () => {
    members = Promise.resolve([member(SELF, true, 'p-self'), member(BOB, false, 'p-bob'), member(CAROL, true, 'p-carol')])
    render(<ChatGroupDetails group={group()} />)
    await screen.findByText('Bob')

    fireEvent.click(screen.getByRole('button', { name: /Remove Bob/ }))
    expect(screen.getByText('Remove Bob from the group?')).toBeVisible()
    expect(service.removeChatGroupMember).not.toHaveBeenCalled()
    fireEvent.click(screen.getByTestId('chat-group-member-confirm-action'))
    await waitFor(() => expect(service.removeChatGroupMember).toHaveBeenCalledWith('G'.repeat(43), 'p-bob'))

    fireEvent.click(screen.getByRole('button', { name: /Carol/, pressed: true }))
    expect(screen.getByText('Remove Carol as an admin?')).toBeVisible()
    expect(service.setChatGroupAdmin).not.toHaveBeenCalled()
    fireEvent.click(screen.getByTestId('chat-group-member-confirm-action'))
    await waitFor(() => expect(service.setChatGroupAdmin).toHaveBeenCalledWith('G'.repeat(43), 'p-carol', false))

    fireEvent.click(screen.getByRole('button', { name: /Bob/, pressed: false }))
    await waitFor(() => expect(service.setChatGroupAdmin).toHaveBeenCalledWith('G'.repeat(43), 'p-bob', true))
  })

  it('offers no way to leave while its members are unknown', async () => {
    members = Promise.reject(new Error('offline'))
    render(<ChatGroupDetails group={group()} />)
    expect(await screen.findByRole('alert')).toHaveTextContent("The members couldn't be loaded")
    expect(screen.getByTestId('chat-group-leave')).toBeDisabled()
  })

  it('names only verified members as the next admin', async () => {
    members = Promise.resolve([member(SELF, true, 'p-self'), member(BOB, false, 'p-bob'), member(null, false, 'p-unverified')])
    render(<ChatGroupDetails group={group()} />)
    await screen.findByText('Bob')
    fireEvent.click(screen.getByTestId('chat-group-leave'))
    const radios = await screen.findAllByRole('radio')
    expect(radios).toHaveLength(1)
    expect(screen.getByRole('radio', { name: 'Bob' })).toBeVisible()
  })

  it('says why no admin can be named when nobody else is verified yet', async () => {
    members = Promise.resolve([member(SELF, true, 'p-self'), member(null, false, 'p-unverified')])
    render(<ChatGroupDetails group={group()} />)
    await waitFor(() => expect(screen.getByTestId('chat-group-leave')).toBeEnabled())
    fireEvent.click(screen.getByTestId('chat-group-leave'))
    expect(await screen.findByText(/No other member is verified yet/)).toBeVisible()
    expect(screen.getByTestId('chat-group-leave-confirm')).toBeDisabled()
  })

  it('shows renaming and adding only to those the group allows', async () => {
    members = Promise.resolve([member(SELF, false, 'p-self'), member(BOB, true, 'p-bob')])
    render(<ChatGroupDetails group={group({ attributes: 'administrator', members: 'administrator', addFromInviteLink: 'unsatisfiable' })} />)
    await screen.findByText('Bob')
    expect(screen.queryByTestId('chat-group-rename')).toBeNull()
    expect(screen.queryByTestId('chat-group-add-members')).toBeNull()
    cleanup()

    render(<ChatGroupDetails group={group()} />)
    await screen.findByText('Bob')
    expect(screen.getByTestId('chat-group-rename')).toBeVisible()
    expect(screen.getByTestId('chat-group-add-members')).toBeVisible()
  })
})
