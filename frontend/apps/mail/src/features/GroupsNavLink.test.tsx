import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import type { MailGroup } from '@kutup/mail-core/groups'
import './testI18n'
import { GroupsNavLink } from './GroupsNavLink'

function sidebar(groups: readonly MailGroup[] | undefined) {
  return render(
    <MemoryRouter>
      <ul>
        <GroupsNavLink groups={groups} />
      </ul>
    </MemoryRouter>,
  )
}

describe('the Groups item', () => {
  it('is not shown to an account in no group', () => {
    sidebar([])
    expect(screen.queryByRole('link', { name: 'Groups' })).toBeNull()
  })

  it('is not shown while the groups load', () => {
    sidebar(undefined)
    expect(screen.queryByRole('link', { name: 'Groups' })).toBeNull()
  })

  it('is shown to a member of one group', () => {
    sidebar([{ id: 'g1', kind: 'list', address: 'team@example.test' } as MailGroup])
    expect(screen.getByRole('link', { name: 'Groups' })).toHaveAttribute('href', '/groups')
  })
})
