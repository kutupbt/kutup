import { act, render, screen, waitFor } from '@testing-library/react'
import { BrowserRouter, Navigate, Route, Routes, useParams } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import '../features/testI18n'

// A just-consumed fork names the deep link to open; the app must land
// there, never on the inbox (full test: specs 174 and 175).
const boot = vi.hoisted(() => ({ next: '/settings/filters' as string | undefined }))
vi.mock('@kutup/session/childBoot', () => ({
  bootChildApp: () => Promise.resolve({ kind: 'ready', next: boot.next }),
}))
const { Boot } = await import('./Boot')

function Folder() {
  const { folder } = useParams()
  // As MailboxPage: an unknown folder (here /login) goes to the inbox.
  if (folder !== 'inbox') return <Navigate to="/inbox" replace />
  return <p>inbox page</p>
}

function App() {
  return (
    <BrowserRouter>
      <Boot>
        <Routes>
          <Route path="/:folder" element={<Folder />} />
          <Route path="/settings/filters" element={<p>filters page</p>} />
        </Routes>
      </Boot>
    </BrowserRouter>
  )
}

describe('Boot after a fork', () => {
  it('opens the deep link it was asked for, never the inbox over it', async () => {
    window.history.replaceState(null, '', '/login')
    render(<App />)
    expect(await screen.findByText('filters page')).toBeTruthy()
    // Nothing moves it on afterwards.
    await act(() => new Promise((resolve) => setTimeout(resolve, 50)))
    expect(window.location.pathname).toBe('/settings/filters')
    expect(screen.queryByText('inbox page')).toBeNull()
  })

  it('without a deep link renders where it is', async () => {
    boot.next = undefined
    window.history.replaceState(null, '', '/inbox')
    render(<App />)
    await waitFor(() => expect(screen.getByText('inbox page')).toBeTruthy())
  })
})
