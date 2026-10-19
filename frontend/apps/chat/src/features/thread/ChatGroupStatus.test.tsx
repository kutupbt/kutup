// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import '../media/testI18n'
import type { ChatGroupSummary, ChatGroupSync } from '@kutup/chat-core/types'

let sync: ChatGroupSync = { kind: 'current', revision: 3, keyConfirmed: true }
const syncChatGroup = vi.fn(() => Promise.resolve(sync))
const chat = { service: { syncChatGroup } }
vi.mock('../../app/chatStore', () => ({
  useChat: () => chat,
  refreshChat: vi.fn(() => Promise.resolve(undefined)),
}))

const { ChatGroupStatus } = await import('./ChatGroupStatus')

afterEach(cleanup)

function model(group: Partial<ChatGroupSummary> = {}) {
  return {
    chatGroup: {
      groupId: 'G'.repeat(43),
      title: 'Team',
      status: 'member',
      memberCount: 3,
      forkSuspected: false,
      ...group,
    },
  } as never
}

describe('a pairwise group’s standing above its thread', () => {
  it('says nothing when the group is current with its home', async () => {
    sync = { kind: 'current', revision: 3, keyConfirmed: true }
    render(<ChatGroupStatus model={model()} />)
    await waitFor(() => expect(syncChatGroup).toHaveBeenCalled())
    expect(screen.queryByTestId('chat-group-status')).toBeNull()
  })

  it('warns when the home may be showing different keys, and never hides it', async () => {
    sync = { kind: 'current', revision: 3, keyConfirmed: false }
    render(<ChatGroupStatus model={model()} />)
    expect(
      await screen.findByText(
        "This group's server may be showing you different keys than other members. Messages are still encrypted; verify with a member.",
      ),
    ).toBeVisible()
  })

  it('says the account may have been removed, and when a fork is suspected', async () => {
    sync = { kind: 'maybeRemoved', sinceMs: 1 }
    render(<ChatGroupStatus model={model({ forkSuspected: true })} />)
    expect(await screen.findByText(/You may have been removed from this group/)).toBeVisible()
    expect(screen.getByText(/may be showing members different versions/)).toBeVisible()
  })

  it('catches up only a group the account is in', () => {
    syncChatGroup.mockClear()
    render(<ChatGroupStatus model={model({ status: 'invited' })} />)
    expect(syncChatGroup).not.toHaveBeenCalled()
  })
})
