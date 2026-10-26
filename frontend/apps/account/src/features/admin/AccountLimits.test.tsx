import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import '../../testI18n'

const get = vi.hoisted(() => vi.fn())
const put = vi.hoisted(() => vi.fn())
vi.mock('@kutup/session/client', () => ({ default: { get, put } }))

const { AccountLimits } = await import('./AccountLimits')

const GIB = 1024 * 1024 * 1024
const upload = {
  key: 'drive_upload_max_bytes',
  field: 'driveUploadMaxBytes',
  section: 'drive',
  unit: 'bytes',
  value: 10 * GIB,
  source: 'default',
  siteValue: 10 * GIB,
  min: 1024 * 1024,
  max: 4096 * GIB,
}
const feedback = {
  key: 'rate_limit.feedback',
  limit: 'feedback',
  section: 'administration',
  unit: 'events',
  windowSeconds: 3600,
  value: 5,
  source: 'account',
  siteValue: 10,
  min: 1,
  max: 1000,
}

function view() {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <AccountLimits userId="u1" />
    </QueryClientProvider>,
  )
}

describe("An account's limits", () => {
  it('shows each value in effect and where it comes from, and sets and resets one', async () => {
    get.mockResolvedValue({ data: { settings: [upload], rateLimits: [feedback] } })
    put.mockResolvedValue({ data: { ...upload, value: GIB, source: 'account' } })
    view()
    const row = await screen.findByTestId('admin-rate-limit-drive_upload_max_bytes')
    expect(within(row).getByText("The server's default")).toBeTruthy()
    // A rate limit with the account's own value says so, beside the site's.
    const own = screen.getByTestId('admin-rate-limit-feedback')
    expect(within(own).getByText("This account's own; the server's is 10")).toBeTruthy()

    // Out of range: refused before it is sent.
    const input = within(row).getByTestId('admin-rate-limit-drive_upload_max_bytes-value')
    fireEvent.change(input, { target: { value: '5' } })
    expect(within(row).getByRole('alert')).toBeTruthy()
    fireEvent.change(input, { target: { value: String(GIB) } })
    fireEvent.click(within(row).getByRole('button', { name: 'Save' }))
    await waitFor(() =>
      expect(put).toHaveBeenCalledWith('/admin/users/u1/limits/drive_upload_max_bytes', { value: GIB }),
    )
    // Now the account's own: it can go back to the server's.
    fireEvent.click(await within(row).findByTestId('admin-rate-limit-drive_upload_max_bytes-reset'))
    await waitFor(() =>
      expect(put).toHaveBeenLastCalledWith('/admin/users/u1/limits/drive_upload_max_bytes', { value: null }),
    )
    // A rate limit goes by its prefixed key.
    fireEvent.click(within(own).getByTestId('admin-rate-limit-feedback-reset'))
    await waitFor(() => expect(put).toHaveBeenLastCalledWith('/admin/users/u1/limits/rate_limit.feedback', { value: null }))
  })
})
