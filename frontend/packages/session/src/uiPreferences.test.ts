// @vitest-environment jsdom
import { act, renderHook, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = { theme: 'system', language: 'en' }
const setTheme = vi.fn((theme: string) => {
  state.theme = theme
})
const changeLanguage = vi.fn((language: string) => {
  state.language = language
  return Promise.resolve()
})

vi.mock('next-themes', () => ({ useTheme: () => ({ theme: state.theme, setTheme }) }))
vi.mock('react-i18next', () => ({ useTranslation: () => ({ i18n: { language: state.language, changeLanguage } }) }))
vi.mock('./client', () => ({ default: { get: vi.fn(), put: vi.fn() } }))

const { default: api } = await import('./client')
const { useAccountUiPreferences } = await import('./uiPreferences')
const get = vi.mocked(api.get)
const put = vi.mocked(api.put)

function stored(theme: string | null, language: string | null) {
  get.mockResolvedValue({ data: { theme, language } })
}

describe('useAccountUiPreferences', () => {
  beforeEach(() => {
    state.theme = 'system'
    state.language = 'en'
    vi.clearAllMocks()
    put.mockResolvedValue({ data: {} })
  })

  it("takes the account's theme and language, and does not send them back", async () => {
    stored('dark', 'tr')
    const { rerender } = renderHook(() => useAccountUiPreferences())
    await waitFor(() => expect(setTheme).toHaveBeenCalledWith('dark'))
    expect(changeLanguage).toHaveBeenCalledWith('tr')
    rerender()
    expect(put).not.toHaveBeenCalled()
  })

  it('does not send back a language still on its way while the theme has already changed', async () => {
    stored('dark', 'tr')
    // The language lands a render after the theme.
    changeLanguage.mockImplementationOnce(() => Promise.resolve())
    const { rerender } = renderHook(() => useAccountUiPreferences())
    await waitFor(() => expect(setTheme).toHaveBeenCalledWith('dark'))
    rerender()
    expect(put).not.toHaveBeenCalled()
    state.language = 'tr'
    rerender()
    expect(put).not.toHaveBeenCalled()
  })

  it("makes this app's choice the account's when it never chose", async () => {
    state.theme = 'light'
    stored(null, null)
    renderHook(() => useAccountUiPreferences())
    await waitFor(() => expect(put).toHaveBeenCalledWith('/account/ui-preferences', { theme: 'light', language: 'en' }))
    expect(setTheme).not.toHaveBeenCalled()
  })

  it('saves a change made here', async () => {
    stored('system', 'en')
    const { rerender } = renderHook(() => useAccountUiPreferences())
    await waitFor(() => expect(get).toHaveBeenCalled())
    await act(async () => {})
    state.theme = 'dark'
    rerender()
    expect(put).toHaveBeenCalledWith('/account/ui-preferences', { theme: 'dark', language: 'en' })
    state.language = 'tr-TR'
    rerender()
    expect(put).toHaveBeenLastCalledWith('/account/ui-preferences', { theme: 'dark', language: 'tr' })
  })

  it('reads the account again when the tab comes back into view', async () => {
    stored('system', 'en')
    renderHook(() => useAccountUiPreferences())
    await waitFor(() => expect(get).toHaveBeenCalledTimes(1))
    stored('dark', 'en')
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' })
    document.dispatchEvent(new Event('visibilitychange'))
    await waitFor(() => expect(setTheme).toHaveBeenCalledWith('dark'))
  })

  it('keeps the local choice when the account cannot be read', async () => {
    get.mockRejectedValue(new Error('offline'))
    const { rerender } = renderHook(() => useAccountUiPreferences())
    await waitFor(() => expect(get).toHaveBeenCalled())
    state.theme = 'dark'
    rerender()
    expect(setTheme).not.toHaveBeenCalled()
    // Nothing is saved over an account it has not read.
    expect(put).not.toHaveBeenCalled()
  })
})
