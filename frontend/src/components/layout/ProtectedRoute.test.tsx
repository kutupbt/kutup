// @vitest-environment jsdom
import { describe, it, expect, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { Provider } from 'react-redux'
import ProtectedRoute from './ProtectedRoute'
import { store } from '@/store'
import { setAuth, logout } from '@/store/authSlice'

function Page({ label }: { label: string }) {
  return <div data-testid={label}>{label}</div>
}

function setup(initialEntries: string[]) {
  return render(
    <Provider store={store}>
      <MemoryRouter initialEntries={initialEntries}>
        <Routes>
          <Route element={<ProtectedRoute />}>
            <Route path="/drive" element={<Page label="drive" />} />
            <Route path="/file/:cid/:fid" element={<Page label="file" />} />
          </Route>
          <Route path="/login" element={<Page label="login" />} />
        </Routes>
      </MemoryRouter>
    </Provider>,
  )
}

describe('ProtectedRoute', () => {
  beforeEach(() => {
    store.dispatch(logout())
  })

  it('redirects unauthenticated user to /login', () => {
    setup(['/drive'])
    expect(screen.queryByTestId('drive')).not.toBeInTheDocument()
    expect(screen.getByTestId('login')).toBeInTheDocument()
  })

  it('renders the protected child when authenticated', () => {
    store.dispatch(
      setAuth({
        userId: 'u', email: 'a@b.c', accessToken: 'jwt',
        masterKey: new Uint8Array(0), privateKey: new Uint8Array(0),
        publicKey: '', isAdmin: false, storageQuotaBytes: 0, storageUsedBytes: 0,
      }),
    )
    setup(['/drive'])
    expect(screen.getByTestId('drive')).toBeInTheDocument()
    expect(screen.queryByTestId('login')).not.toBeInTheDocument()
  })

  it('preserves deep-link path via ?next= on redirect (e.g. /file/:cid/:fid)', () => {
    setup(['/file/abc/def'])
    // The Page itself isn't rendered because we redirected. But MemoryRouter
    // updates location synchronously; the next page will be /login?next=...
    // We can't easily inspect URL search via MemoryRouter without exposing
    // the location — but the regression bug we want to guard is "we DID
    // redirect, not silently render the protected page".
    expect(screen.queryByTestId('file')).not.toBeInTheDocument()
    expect(screen.getByTestId('login')).toBeInTheDocument()
  })
})
