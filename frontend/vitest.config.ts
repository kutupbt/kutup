import { createRequire } from 'node:module'
import path from 'node:path'
import { defineConfig } from 'vitest/config'

// The ESM build of libsodium-wrappers-sumo has a broken relative import for
// libsodium-sumo.mjs; force the CJS build (its package "main").
const requireFromCrypto = createRequire(path.resolve(__dirname, 'packages/crypto/package.json'))
const libsodiumCjs = requireFromCrypto.resolve('libsodium-wrappers-sumo')

export default defineConfig({
  resolve: {
    alias: { 'libsodium-wrappers-sumo': libsodiumCjs },
  },
  test: {
    include: ['packages/*/src/**/*.test.{ts,tsx}', 'apps/*/src/**/*.test.{ts,tsx}'],
    environment: 'jsdom',
    globals: false,
    setupFiles: ['./vitest.setup.ts'],
    environmentOptions: {
      // A real URL so axios can resolve relative paths like '/api'.
      jsdom: { url: 'http://localhost/' },
    },
  },
})
