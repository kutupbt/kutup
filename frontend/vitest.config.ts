import { defineConfig } from 'vitest/config'
import path from 'path'

export default defineConfig({
  test: {
    // jsdom by default so component tests + sessionStorage-touching code
    // work. Pure-node tests (crypto/, collab/) are unaffected — they don't
    // touch window/document.
    environment: 'jsdom',
    globals: false,
    setupFiles: ['./vitest.setup.ts'],
    environmentOptions: {
      jsdom: {
        // Anchor jsdom to a real URL so axios's fetch adapter can resolve
        // relative paths like baseURL: '/api'. Without this jsdom defaults
        // to "about:blank" which the URL parser rejects.
        url: 'http://localhost/',
      },
    },
  },
  resolve: {
    alias: {
      // Mirror vite.config.ts: the ESM build of libsodium-wrappers-sumo has a
      // broken relative import for libsodium-sumo.mjs (the file lives in a
      // separate package). Force the CJS build so Node-resolve works under
      // Vitest.
      'libsodium-wrappers-sumo': path.resolve(
        __dirname,
        'node_modules/libsodium-wrappers-sumo/dist/modules-sumo/libsodium-wrappers.js',
      ),
    },
  },
})
