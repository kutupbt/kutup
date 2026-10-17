import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import '../../testI18n'

const flows = vi.hoisted(() => ({
  signIn: vi.fn(),
  completeTotp: vi.fn(),
  abandonTotp: vi.fn(),
}))
vi.mock('./flows', () => flows)
vi.mock('@kutup/session/store', () => ({ useSession: () => null }))
vi.mock('@kutup/crypto/opaqueWorker', () => ({ OpaqueWorkerClosed: class OpaqueWorkerClosed extends Error {} }))
vi.mock('./errors', () => ({
  authErrorMessage: () => 'failed',
  bodyCode: (error: { code?: string }) => error.code,
}))

const { LoginPage } = await import('./LoginPage')
const { OpaqueWorkerClosed } = await import('@kutup/crypto/opaqueWorker')

const challenge = { name: 'alice', preAuthToken: 'pre', signIn: {} }

async function reachCodeStep() {
  flows.signIn.mockResolvedValue({ kind: 'totp', challenge })
  const view = render(
    <MemoryRouter>
      <LoginPage />
    </MemoryRouter>,
  )
  fireEvent.change(screen.getByLabelText('Username', { exact: true }), { target: { value: 'alice' } })
  fireEvent.change(screen.getByLabelText('Password', { exact: true }), { target: { value: 'pw' } })
  fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))
  await screen.findByLabelText('Authentication code')
  return view
}

beforeEach(() => {
  for (const fn of Object.values(flows)) fn.mockReset()
})

describe('the code step', () => {
  it('ends the waiting sign-in when the page goes away', async () => {
    const view = await reachCodeStep()
    expect(flows.abandonTotp).not.toHaveBeenCalled()
    view.unmount()
    expect(flows.abandonTotp).toHaveBeenCalledWith(challenge)
  })

  it('ends it when the person goes back', async () => {
    await reachCodeStep()
    fireEvent.click(screen.getByRole('button', { name: 'Use a different account' }))
    await screen.findByLabelText('Username', { exact: true })
    expect(flows.abandonTotp).toHaveBeenCalledWith(challenge)
  })

  it('starts over when the sign-in itself ended after the code', async () => {
    await reachCodeStep()
    flows.completeTotp.mockRejectedValue(new OpaqueWorkerClosed())
    fireEvent.change(screen.getByLabelText('Authentication code'), { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }))
    await screen.findByLabelText('Username', { exact: true })
    await waitFor(() => expect(screen.getByText('The sign-in ended before it finished. Sign in again.')).toBeTruthy())
  })

  it('a first step that ran out goes back to the password; a wrong code stays on the code', async () => {
    await reachCodeStep()
    flows.completeTotp.mockRejectedValueOnce(Object.assign(new Error('401'), { code: 'invalidCredentials' }))
    fireEvent.change(screen.getByLabelText('Authentication code'), { target: { value: '000000' } })
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }))
    await screen.findByText('failed')
    expect(screen.getByLabelText('Authentication code')).toBeTruthy()
    expect(flows.abandonTotp).not.toHaveBeenCalled()
    flows.completeTotp.mockRejectedValueOnce(Object.assign(new Error('401'), { code: 'preAuthInvalid' }))
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }))
    await screen.findByLabelText('Username', { exact: true })
    expect(flows.abandonTotp).toHaveBeenCalledWith(challenge)
  })
})
