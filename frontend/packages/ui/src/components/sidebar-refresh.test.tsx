import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { Inbox, Send } from 'lucide-react'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import { SidebarNavLink } from './app-shell'

function Where() {
  return <p data-testid="where">{useLocation().pathname + useLocation().search}</p>
}

function renderAt(path: string, run: () => Promise<unknown>) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <ul>
        <SidebarNavLink to="/inbox" icon={<Inbox />} label="Inbox" refresh={{ label: 'Refresh Inbox', run }} />
        <SidebarNavLink to="/sent" icon={<Send />} label="Sent" refresh={{ label: 'Refresh Sent', run }} />
      </ul>
      <Routes>
        <Route path="*" element={<Where />} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('the sidebar refresh (Proton)', () => {
  it('refreshes when the open place is clicked again, and spins while it does', async () => {
    const run = vi.fn(() => Promise.resolve())
    renderAt('/inbox', run)
    fireEvent.click(screen.getByRole('link', { name: 'Inbox' }))
    expect(run).toHaveBeenCalledTimes(1)
    expect(screen.getByRole('button', { name: 'Refresh Inbox' })).toHaveAttribute('aria-busy', 'true')
    // A second click while it spins starts no second fetch.
    fireEvent.click(screen.getByRole('link', { name: 'Inbox' }))
    expect(run).toHaveBeenCalledTimes(1)
    await waitFor(() => expect(screen.getByRole('button', { name: 'Refresh Inbox' })).toHaveAttribute('aria-busy', 'false'), { timeout: 2000 })
  })

  it('shows the button on the open place only, and it refreshes', () => {
    const run = vi.fn(() => Promise.resolve())
    renderAt('/inbox', run)
    expect(screen.queryByRole('button', { name: 'Refresh Sent' })).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Refresh Inbox' }))
    expect(run).toHaveBeenCalledTimes(1)
  })

  it('navigates as before from another place, or from a later page of the same one', () => {
    const run = vi.fn(() => Promise.resolve())
    renderAt('/inbox?page=2', run)
    fireEvent.click(screen.getByRole('link', { name: 'Inbox' }))
    expect(run).not.toHaveBeenCalled()
    expect(screen.getByTestId('where')).toHaveTextContent('/inbox')
    expect(screen.getByTestId('where')).not.toHaveTextContent('page=2')
    fireEvent.click(screen.getByRole('link', { name: 'Sent' }))
    expect(run).not.toHaveBeenCalled()
    expect(screen.getByTestId('where')).toHaveTextContent('/sent')
  })
})
