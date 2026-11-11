import { defineConfig } from 'vite'
import { kutupApp } from '@kutup/config/vite'

export default defineConfig(kutupApp({ app: 'pass', wasm: ['crypto', 'pass'] }))
