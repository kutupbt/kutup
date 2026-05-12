import { describe, it, expect, beforeEach, vi } from 'vitest'

// Test matrix:
//   • !isTauri               → '/api' regardless of getServerUrl
//   • isTauri + serverUrl    → '${serverUrl}/api'
//   • isTauri + no serverUrl → '/api' (graceful fallback so dev isn't broken)
//
// We re-import the module in each test after stubbing so cached state from a
// prior test doesn't bleed in.

const getServerUrlMock = vi.fn<() => Promise<string | null>>()
const getServerInsecureMock = vi.fn<() => Promise<boolean>>(async () => false)

vi.mock('./serverConfig', () => ({
  getServerUrl: () => getServerUrlMock(),
  getServerInsecure: () => getServerInsecureMock(),
  setServerUrl: vi.fn(),
  setServerInsecure: vi.fn(),
  clearServerUrl: vi.fn(),
  primeInsecureCache: vi.fn(),
  resetInsecureCache: vi.fn(),
}))

const isTauriMock = vi.hoisted(() => ({ value: false }))
vi.mock('./isTauri', () => ({
  get isTauri() {
    return isTauriMock.value
  },
}))

async function loadFreshModule() {
  vi.resetModules()
  return await import('./apiBase')
}

describe('apiBase', () => {
  beforeEach(() => {
    getServerUrlMock.mockReset()
    isTauriMock.value = false
  })

  it('returns /api on the web (no Tauri)', async () => {
    isTauriMock.value = false
    const { resolveApiBase, apiBase } = await loadFreshModule()
    await expect(resolveApiBase()).resolves.toBe('/api')
    expect(apiBase()).toBe('/api')
    expect(getServerUrlMock).not.toHaveBeenCalled()
  })

  it('returns ${serverUrl}/api in Tauri with a stored URL', async () => {
    isTauriMock.value = true
    getServerUrlMock.mockResolvedValue('https://kutup.example.com')
    const { resolveApiBase, apiBase } = await loadFreshModule()
    await expect(resolveApiBase()).resolves.toBe(
      'https://kutup.example.com/api',
    )
    expect(apiBase()).toBe('https://kutup.example.com/api')
  })

  it('falls back to /api in Tauri when no serverUrl is stored', async () => {
    isTauriMock.value = true
    getServerUrlMock.mockResolvedValue(null)
    const { resolveApiBase } = await loadFreshModule()
    await expect(resolveApiBase()).resolves.toBe('/api')
  })

  it('apiBase() throws if called before resolveApiBase() settles', async () => {
    isTauriMock.value = false
    const { apiBase } = await loadFreshModule()
    expect(() => apiBase()).toThrow(/before resolveApiBase/)
  })

  it('invalidateApiBase() allows re-resolution with a new URL', async () => {
    isTauriMock.value = true
    getServerUrlMock.mockResolvedValueOnce('https://first.example')
    const { resolveApiBase, invalidateApiBase } = await loadFreshModule()
    await expect(resolveApiBase()).resolves.toBe('https://first.example/api')

    invalidateApiBase()
    getServerUrlMock.mockResolvedValueOnce('https://second.example')
    await expect(resolveApiBase()).resolves.toBe('https://second.example/api')
  })

  it('concurrent resolveApiBase() calls share one warmup', async () => {
    isTauriMock.value = true
    let resolveStored: (v: string | null) => void = () => {}
    getServerUrlMock.mockImplementation(
      () =>
        new Promise<string | null>((r) => {
          resolveStored = r
        }),
    )
    const { resolveApiBase } = await loadFreshModule()
    const a = resolveApiBase()
    const b = resolveApiBase()
    resolveStored('https://shared.example')
    await expect(a).resolves.toBe('https://shared.example/api')
    await expect(b).resolves.toBe('https://shared.example/api')
    expect(getServerUrlMock).toHaveBeenCalledTimes(1)
  })
})
