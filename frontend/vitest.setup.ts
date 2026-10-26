// Vitest setup file — loaded before each test file under jsdom env.
// Adds @testing-library/jest-dom matchers (toBeInTheDocument, toHaveTextContent…)
// to expect(), and ensures the React tree is unmounted between tests so DOM
// queries don't leak across them.
import '@testing-library/jest-dom/vitest'
import { afterEach, expect } from 'vitest'
import { cleanup } from '@testing-library/react'

afterEach(() => {
  cleanup()
})

// toEqual on typed arrays compares them byte for byte here. The default walks
// every element as an object key, which takes about a minute for one 5 MiB
// secretstream chunk; this takes milliseconds. Arrays of different kinds or
// other values fall through to the default.
expect.addEqualityTesters([
  function typedArraysEqual(a: unknown, b: unknown) {
    if (!ArrayBuffer.isView(a) || !ArrayBuffer.isView(b) || a instanceof DataView || b instanceof DataView) return undefined
    if (Object.prototype.toString.call(a) !== Object.prototype.toString.call(b)) return undefined
    const x = a as unknown as ArrayLike<number | bigint>
    const y = b as unknown as ArrayLike<number | bigint>
    if (x.length !== y.length) return false
    for (let i = 0; i < x.length; i++) if (!Object.is(x[i], y[i])) return false
    return true
  },
])

// jsdom doesn't ship URL.createObjectURL / revokeObjectURL by default.
// Provide stub no-ops so components that use them at render time don't crash;
// individual tests that care about the value can vi.spyOn() these.
if (typeof URL.createObjectURL !== 'function') {
  URL.createObjectURL = (() => 'blob:stub') as typeof URL.createObjectURL
  URL.revokeObjectURL = () => undefined
}

// jsdom doesn't ship window.matchMedia. Provide a stub (matches: false →
// the "no OS preference → light" path) so code that calls it doesn't crash;
// tests that care can vi.spyOn(window, 'matchMedia').
if (typeof window !== 'undefined' && typeof window.matchMedia !== 'function') {
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
