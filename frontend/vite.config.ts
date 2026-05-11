import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'

export default defineConfig({
  plugins: [tailwindcss(), react()],
  worker: {
    format: 'es',
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
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
        // The docker compose stack at https://localhost:38443 (self-signed
        // cert, single-user dev box). `secure: false` accepts the cert;
        // `ws: true` upgrades collab WebSocket connections.
        target: 'https://localhost:38443',
        changeOrigin: true,
        secure: false,
        ws: true,
      },
    },
  },
})
