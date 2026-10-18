import { render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { resetWebAssemblyProbe, webAssemblySupported } from '../lib/webAssembly'
import { WebAssemblyGate } from './webassembly-gate'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}))

afterEach(() => {
  vi.unstubAllGlobals()
  resetWebAssemblyProbe()
})

describe('WebAssemblyGate', () => {
  it('renders the app where WebAssembly runs', () => {
    expect(webAssemblySupported()).toBe(true)
    render(
      <WebAssemblyGate>
        <p>the app</p>
      </WebAssemblyGate>,
    )
    expect(screen.getByText('the app')).toBeTruthy()
  })

  it('explains, with the Lockdown Mode steps, where WebAssembly is off', () => {
    // Safari's Lockdown Mode: no WebAssembly object at all.
    vi.stubGlobal('WebAssembly', undefined)
    render(
      <WebAssemblyGate>
        <p>the app</p>
      </WebAssemblyGate>,
    )
    expect(screen.queryByText('the app')).toBeNull()
    expect(screen.getByRole('heading', { name: 'webAssembly.title' })).toBeTruthy()
    expect(screen.getByText('webAssembly.lockdownStep2')).toBeTruthy()
  })

  it('treats a WebAssembly that refuses to compile as off', () => {
    vi.stubGlobal('WebAssembly', {
      Module: function () {
        throw new Error('WebAssembly is disabled')
      },
      Instance: function () {},
    })
    expect(webAssemblySupported()).toBe(false)
  })
})
