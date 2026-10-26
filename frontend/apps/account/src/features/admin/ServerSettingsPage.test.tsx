import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import '../../testI18n'

const get = vi.hoisted(() => vi.fn())
const put = vi.hoisted(() => vi.fn())
vi.mock('@kutup/session/client', () => ({ default: { get, put } }))

const { ServerSettingsPage } = await import('./ServerSettingsPage')

const settings = {
  registrationMode: 'off',
  defaultStorageQuotaBytes: 5 * 1024 ** 3,
  chatMailboxRetentionDays: 30,
  chatMediaDeliveryRetentionDays: 30,
  chatGroupLinkJoinsPerRelayGroupPerMin: 10,
  chatGroupLinkJoinsPerRelayPerMin: 100,
  chatGroupAvatarMaxBytes: 41001,
  chatGroupAvatarStoragePerGroupBytes: 82002,
  chatGroupAvatarPendingSeconds: 3600,
  passVaultMaxBytes: 64 * 1024 * 1024,
  driveStreamCacheBlocks: 3,
}
const registry = [
  {
    key: 'drive_stream_cache_blocks',
    field: 'driveStreamCacheBlocks',
    section: 'drive',
    unit: 'count',
    default: 3,
    min: 2,
    max: 9,
    perAccount: true,
    value: 3,
    set: false,
  },
]

describe('Administration → Server settings', () => {
  it("takes each whole-number field and its range from the server's registry", async () => {
    get.mockImplementation(async (path: string) => ({
      data: path === '/admin/settings/registry' ? { settings: registry } : settings,
    }))
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <ServerSettingsPage />
      </QueryClientProvider>,
    )
    const field = (await screen.findByLabelText(/Blocks kept per stream/)) as HTMLInputElement
    expect(field.min).toBe('2')
    expect(field.max).toBe('9')
    expect(field.value).toBe('3')
  })
})
