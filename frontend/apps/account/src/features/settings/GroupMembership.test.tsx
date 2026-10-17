import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { MailGroup } from '@kutup/mail-core/groups'
import '../../testI18n'

let groups: { isPending: boolean; isError: boolean; data: MailGroup[] | undefined }
vi.mock('@kutup/mail-core/groups', () => ({ useMyGroups: () => groups }))
vi.mock('@kutup/mail-core/api', () => ({ useMailAccount: () => ({ data: undefined }) }))
vi.mock('@kutup/mail-core/ui/GroupDialog', () => ({ GroupDialog: () => null }))
vi.mock('@kutup/session/store', () => ({ useRequiredSession: () => ({ isAdmin: false }) }))
vi.mock('@kutup/session/apps', () => ({ appUrl: (app: string, path = '/') => `https://${app}.example.test${path}` }))

const { GroupMembershipNavLink } = await import('./GroupMembershipNavLink')
const { GroupMembershipPage } = await import('./GroupMembershipPage')

const loading = { isPending: true, isError: false, data: undefined }
const none = { isPending: false, isError: false, data: [] }
const two = {
  isPending: false,
  isError: false,
  data: [
    { id: 'g1', kind: 'shared', address: 'hr@kutup.test', displayName: 'HR', memberCount: 3, myRole: 'manager' },
    { id: 'g2', kind: 'list', address: 'team@kutup.test', displayName: '', memberCount: 12, myRole: 'member' },
  ] as MailGroup[],
}

function menu() {
  return render(
    <MemoryRouter>
      <ul>
        <GroupMembershipNavLink />
      </ul>
    </MemoryRouter>,
  )
}

describe('Group membership in the settings menu', () => {
  beforeEach(() => {
    groups = none
  })

  it('is hidden from an account in no group', () => {
    menu()
    expect(screen.queryByRole('link', { name: 'Group membership' })).toBeNull()
  })

  it('is hidden while the groups load', () => {
    groups = loading
    menu()
    expect(screen.queryByRole('link', { name: 'Group membership' })).toBeNull()
  })

  it('is shown to a member of a group', () => {
    groups = two
    menu()
    expect(screen.getByRole('link', { name: 'Group membership' })).toHaveAttribute('href', '/settings/groups')
  })
})

describe('the Group membership page', () => {
  it('lists each group with its kind, address and the account’s role', () => {
    groups = two
    render(<GroupMembershipPage />)
    const [hr, team] = screen.getAllByRole('listitem')
    expect(within(hr).getByText('HR')).toBeVisible()
    expect(within(hr).getByText(/hr@kutup\.test · Shared mailbox/)).toBeVisible()
    expect(within(hr).getByText('Manager')).toBeVisible()
    expect(within(hr).getByRole('link', { name: 'Open' })).toHaveAttribute('href', 'https://mail.example.test/g/g1/inbox')
    expect(within(hr).getByRole('button', { name: 'Manage' })).toBeVisible()
    expect(within(team).getByText(/team@kutup\.test · Distribution list/)).toBeVisible()
    expect(within(team).getByText('Member')).toBeVisible()
    expect(within(team).queryByRole('link', { name: 'Open' })).toBeNull()
    expect(within(team).getByRole('button', { name: 'Members' })).toBeVisible()
  })

  it('opened with no groups, says so', () => {
    groups = none
    render(<GroupMembershipPage />)
    expect(screen.getByText('You are not in any groups')).toBeVisible()
  })
})
