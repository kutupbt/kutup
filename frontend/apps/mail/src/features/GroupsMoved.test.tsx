import { render } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { setAppDirectoryForTesting } from '@kutup/session/apps'
import { GroupsMoved } from './GroupsMoved'

afterEach(() => {
  setAppDirectoryForTesting(null)
  vi.unstubAllGlobals()
})

describe("Mail's old Groups address", () => {
  it('goes to Group membership in Account settings', () => {
    setAppDirectoryForTesting({ account: 'https://account.example.test/' } as Parameters<typeof setAppDirectoryForTesting>[0])
    const replace = vi.fn()
    vi.stubGlobal('location', { ...window.location, replace })
    render(
      <MemoryRouter initialEntries={['/groups']}>
        <Routes>
          <Route path="/groups" element={<GroupsMoved />} />
        </Routes>
      </MemoryRouter>,
    )
    expect(replace).toHaveBeenCalledWith('https://account.example.test/settings/groups')
  })
})
