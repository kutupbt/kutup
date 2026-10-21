import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import '../../testI18n'

const get = vi.hoisted(() => vi.fn())
const put = vi.hoisted(() => vi.fn())
vi.mock('@kutup/session/client', () => ({ default: { get, put } }))

const { RateLimitsPage } = await import('./RateLimitsPage')

const login = {
  key: 'login',
  section: 'accounts',
  per: 'address',
  unit: 'events',
  windowSeconds: 60,
  about: 'Sign-in attempts (and their second factor).',
  value: 10,
  firstValue: 10,
  firstFrom: 'default',
  env: 'RATE_LIMIT_LOGIN_PER_MIN',
  set: false,
  min: 1,
  max: 1000,
}
const imageBytes = {
  ...login,
  key: 'mail_image_bytes',
  section: 'mail',
  per: 'account',
  unit: 'bytes',
  value: 64 * 1024 * 1024,
  firstValue: 64 * 1024 * 1024,
  env: null,
  max: 6400 * 1024 * 1024,
}

function page() {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <RateLimitsPage />
    </QueryClientProvider>,
  )
}

describe('Administration → Rate limits', () => {
  it('lists limits by section with what they count, and saves a value in bounds', async () => {
    get.mockResolvedValue({ data: { limits: [login, imageBytes] } })
    put.mockResolvedValue({ data: { ...login, value: 20, set: true } })
    page()
    const row = await screen.findByTestId('admin-rate-limit-login')
    expect(within(row).getByText('Sign-in attempts (and their second factor).')).toBeTruthy()
    expect(within(row).getByText('Per address each minute')).toBeTruthy()
    // A byte limit shows its size.
    expect(within(screen.getByTestId('admin-rate-limit-mail_image_bytes')).getByText(/MB|MiB/)).toBeTruthy()

    const input = within(row).getByTestId('admin-rate-limit-login-value')
    fireEvent.change(input, { target: { value: '1001' } })
    expect(within(row).getByRole('alert').textContent).toContain('1000')
    expect(within(row).getByRole('button', { name: 'Save' })).toHaveProperty('disabled', true)

    fireEvent.change(input, { target: { value: '20' } })
    fireEvent.click(within(row).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(put).toHaveBeenCalledWith('/admin/rate-limits/login', { value: 20 }))
    // Set here: it can be reset to its first value.
    fireEvent.click(await within(row).findByTestId('admin-rate-limit-login-reset'))
    await waitFor(() => expect(put).toHaveBeenLastCalledWith('/admin/rate-limits/login', { value: null }))
  })
})
