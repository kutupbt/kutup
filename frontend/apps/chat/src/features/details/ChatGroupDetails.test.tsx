// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import '../media/testI18n'
import type { ChatGroupDetails as Details, ChatGroupMember, ChatGroupSummary } from '@kutup/chat-core/types'

const SELF = 'aci:00000000-0000-4000-8000-00000000000e@a.test'
const BOB = 'aci:00000000-0000-4000-8000-0000000000b2@a.test'
const CAROL = 'aci:00000000-0000-4000-8000-0000000000c3@a.test'

let members: Promise<ChatGroupMember[]>
let details: Details
const service = {
  chatGroupMembers: vi.fn(() => members),
  chatGroupDetails: vi.fn(() => Promise.resolve(details)),
  approveChatGroupRequest: vi.fn(() => Promise.resolve(undefined)),
  denyChatGroupRequest: vi.fn(() => Promise.resolve(undefined)),
  banChatGroupMember: vi.fn(() => Promise.resolve(undefined)),
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
  details = settings()
})

function settings(over: Partial<Details> = {}): Details {
  return {
    groupId: 'G'.repeat(43),
    title: 'Team',
    timerSeconds: 0,
    announcementsOnly: false,
    terminated: false,
    access: { attributes: 'member', members: 'member', addFromInviteLink: 'unsatisfiable' },
    link: { mode: 'off' },
    administrator: true,
    requests: [],
    bans: [],
    bannedMembers: [],
    banListFull: false,
    ...over,
  }
}
details = settings()

const member = (account: string | null, administrator: boolean, pseudonym: string): ChatGroupMember => ({
  pseudonym,
  administrator,
  joinedAtRevision: 1,
  account,
})

function group(access: ChatGroupSummary['access'] = { attributes: 'member', members: 'member', addFromInviteLink: 'unsatisfiable' }): ChatGroupSummary {
  return { groupId: 'G'.repeat(43), title: 'Team', status: 'member', revision: 3, memberCount: 3, forkSuspected: false, access, maySend: true, announcementsOnly: false, terminated: false, timerSeconds: 0 }
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

  it('lets an administrator approve or deny a request, never a banned account', async () => {
    members = Promise.resolve([member(SELF, true, 'p-self'), member(BOB, false, 'p-bob')])
    details = settings({
      requests: [
        { pseudonym: 'p-carol', requestedAtRevision: 4, account: CAROL, banned: false },
        { pseudonym: 'p-dave', requestedAtRevision: 5, account: null, banned: true },
      ],
    })
    render(<ChatGroupDetails group={group()} />)
    const carol = await screen.findByTestId(`chat-group-request-${CAROL}`)
    fireEvent.click(carol.querySelector('[data-testid="chat-group-request-approve"]')!)
    await waitFor(() => expect(service.approveChatGroupRequest).toHaveBeenCalledWith('G'.repeat(43), 'p-carol'))
    const dave = screen.getByTestId('chat-group-request-p-dave')
    expect(dave.querySelector('[data-testid="chat-group-request-approve"]')).toBeDisabled()
    fireEvent.click(dave.querySelector('[data-testid="chat-group-request-deny"]')!)
    await waitFor(() => expect(service.denyChatGroupRequest).toHaveBeenCalledWith('G'.repeat(43), 'p-dave'))
  })

  it('bans with a new link by default while the link is on', async () => {
    members = Promise.resolve([member(SELF, true, 'p-self'), member(BOB, false, 'p-bob')])
    details = settings({ link: { mode: 'join', fragment: 'AQ' }, bannedMembers: ['p-bob'] })
    render(<ChatGroupDetails group={group()} />)
    await screen.findByText('Bob')
    expect(screen.getByTestId('chat-group-member-banned')).toBeVisible()
    expect(screen.getByTestId('chat-group-remove-unverified')).toBeVisible()
    fireEvent.click(screen.getByTestId('chat-group-member-ban'))
    expect(screen.getByTestId('chat-group-ban-reset')).toBeChecked()
    fireEvent.click(screen.getByTestId('chat-group-ban-confirm'))
    await waitFor(() => expect(service.banChatGroupMember).toHaveBeenCalledWith('G'.repeat(43), 'p-bob', true))
  })

  it('says plainly when the ban list is full', async () => {
    members = Promise.resolve([member(SELF, true, 'p-self'), member(BOB, false, 'p-bob')])
    details = settings({ banListFull: true, bans: [{ account: CAROL, pseudonyms: ['p-carol'] }] })
    render(<ChatGroupDetails group={group()} />)
    expect(await screen.findByTestId('chat-group-ban-list-full')).toHaveTextContent('The ban list is full')
    fireEvent.click(await screen.findByTestId('chat-group-member-ban'))
    expect(screen.getByTestId('chat-group-ban-dialog')).toHaveTextContent('The ban list is full')
  })

  it('offers nothing to change once the group has ended', async () => {
    members = Promise.resolve([member(SELF, true, 'p-self'), member(BOB, false, 'p-bob')])
    details = settings({ terminated: true })
    render(<ChatGroupDetails group={group()} />)
    expect(await screen.findByTestId('chat-group-ended')).toBeVisible()
    expect(screen.queryByTestId('chat-group-rename')).toBeNull()
    expect(screen.queryByTestId('chat-group-member-remove')).toBeNull()
    expect(screen.queryByTestId('chat-group-end')).toBeNull()
  })
})
