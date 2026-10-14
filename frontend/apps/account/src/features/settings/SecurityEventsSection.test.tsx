import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { AxiosError, AxiosHeaders, type AxiosResponse } from 'axios'
import { describe, expect, it, vi } from 'vitest'
import '../../testI18n'

const get = vi.hoisted(() => vi.fn())
vi.mock('@kutup/session/client', () => ({ default: { get } }))

const { SecurityEventsSection } = await import('./SecurityEventsSection')

const event = (id: string, kind = 'passwordChange') => ({ id, kind, at: '2026-10-14T10:00:00Z', thisSession: false, client: null, userAgent: null, byAdmin: false })

function badCursor(): AxiosError {
  const response = { status: 400, data: { error: 'unknown cursor' }, headers: {}, config: { headers: new AxiosHeaders() }, statusText: '' } as AxiosResponse
  return new AxiosError('bad', '400', undefined, undefined, response)
}

describe('the security events list', () => {
  it('starts again from the newest when the server no longer knows the cursor', async () => {
    let first = true
    get.mockImplementation((_path: string, { params }: { params: { cursor?: string } }) => {
      if (params.cursor) return Promise.reject(badCursor())
      const page = first ? { events: [event('e1')], next: 'e1' } : { events: [event('e0', 'recovery')], next: null }
      first = false
      return Promise.resolve({ data: page })
    })
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <SecurityEventsSection />
      </QueryClientProvider>,
    )
    fireEvent.click(await screen.findByRole('button', { name: 'Show older events' }))
    await screen.findByText('Password reset with the recovery phrase')
    expect(get.mock.calls.map(([, options]) => (options as { params: { cursor?: string } }).params.cursor)).toEqual([undefined, 'e1', undefined])
    await waitFor(() => expect(screen.queryByText('Security events could not be loaded.')).toBeNull())
  })
})
