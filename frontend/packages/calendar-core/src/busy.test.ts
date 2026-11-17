import { beforeEach, describe, expect, it, vi } from 'vitest'

const server = vi.hoisted(() => ({ busy: [] as unknown[], settings: {}, get: vi.fn() }))
vi.mock('@kutup/session/client', () => ({
  default: {
    get: (url: string, config: unknown) => {
      server.get(url, config)
      return Promise.resolve({ data: { busy: server.busy } })
    },
  },
}))
vi.mock('@kutup/session/apps', () => ({ loadServerSettings: () => Promise.resolve(server.settings) }))

const { BusyWindowTooLong, loadBusy } = await import('./busy')

beforeEach(() => {
  server.busy = []
  server.settings = {}
  server.get.mockReset()
})

describe('busy times', () => {
  it('asks for the person and the window, and answers the blocks in order, overlaps merged', async () => {
    server.busy = [
      { startUtc: '2026-11-20T10:00:00Z', endUtc: '2026-11-20T11:00:00Z', fullDay: false },
      { startUtc: '2026-11-20T09:00:00Z', endUtc: '2026-11-20T10:30:00Z', fullDay: false },
      { startUtc: '2026-11-21T00:00:00Z', endUtc: '2026-11-22T00:00:00Z', fullDay: true },
      // Outside the window, and backwards: not taken.
      { startUtc: '2026-12-20T09:00:00Z', endUtc: '2026-12-20T10:00:00Z', fullDay: false },
      { startUtc: '2026-11-20T15:00:00Z', endUtc: '2026-11-20T14:00:00Z', fullDay: false },
    ]
    const blocks = await loadBusy(' bo@kutup.test ', '2026-11-16T00:00:00Z', '2026-11-23T00:00:00Z')
    expect(server.get).toHaveBeenCalledWith('/calendar/busy', { params: { address: 'bo@kutup.test', start: '2026-11-16T00:00:00Z', end: '2026-11-23T00:00:00Z' } })
    expect(blocks).toEqual([
      { startUtc: '2026-11-20T09:00:00Z', endUtc: '2026-11-20T11:00:00Z', fullDay: false },
      { startUtc: '2026-11-21T00:00:00Z', endUtc: '2026-11-22T00:00:00Z', fullDay: true },
    ])
  })

  it('asks no more than the window the server answers', async () => {
    server.settings = { calendar: { busyWindowDays: 7 } }
    await expect(loadBusy('bo@kutup.test', '2026-11-01T00:00:00Z', '2026-11-30T00:00:00Z')).rejects.toBeInstanceOf(BusyWindowTooLong)
    await expect(loadBusy('bo@kutup.test', '2026-11-02T00:00:00Z', '2026-11-01T00:00:00Z')).rejects.toThrow()
    expect(server.get).not.toHaveBeenCalled()
  })
})
