import { defineConfig } from 'vitest/config'
import path from 'path'

export default defineConfig({
  test: {
    environment: 'node',
    globals: false,
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
