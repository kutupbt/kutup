import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  worker: {
    format: 'es',
  },
  resolve: {
    alias: {
      // Force Vite to use the CJS build — the ESM build has a broken relative
      // import for libsodium-sumo.mjs that Rollup cannot resolve.
      'libsodium-wrappers-sumo': path.resolve(
        __dirname,
        'node_modules/libsodium-wrappers-sumo/dist/modules-sumo/libsodium-wrappers.js',
      ),
    },
  },
  optimizeDeps: {
    include: ['libsodium-wrappers-sumo', 'buffer'],
  },
  build: {
    target: 'esnext',
  },
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:3000',
        changeOrigin: true,
      },
    },
  },
})
