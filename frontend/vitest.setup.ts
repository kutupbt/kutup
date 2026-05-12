// Vitest setup file — loaded before each test file under jsdom env.
// Adds @testing-library/jest-dom matchers (toBeInTheDocument, toHaveTextContent…)
// to expect(), and ensures the React tree is unmounted between tests so DOM
// queries don't leak across them.
import '@testing-library/jest-dom/vitest'
import { afterEach } from 'vitest'
import { cleanup } from '@testing-library/react'

afterEach(() => {
  cleanup()
})

// jsdom doesn't ship URL.createObjectURL / revokeObjectURL by default.
// Provide stub no-ops so components that use them at render time don't crash;
// individual tests that care about the value can vi.spyOn() these.
if (typeof URL.createObjectURL !== 'function') {
  // @ts-expect-error — augmenting a global for the test environment.
  URL.createObjectURL = () => 'blob:stub'
  // @ts-expect-error
  URL.revokeObjectURL = () => undefined
}

// jsdom doesn't ship window.matchMedia. Provide a stub (matches: false →
// the "no OS preference → light" path) so code that calls it doesn't crash;
// tests that care can vi.spyOn(window, 'matchMedia').
if (typeof window !== 'undefined' && typeof window.matchMedia !== 'function') {
  // @ts-expect-error — augmenting a global for the test environment.
  window.matchMedia = (query: string): MediaQueryList =>
    ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }) as unknown as MediaQueryList
}
