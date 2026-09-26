import { defineConfig } from 'vite'
import { kutupApp } from '@kutup/config/vite'

export default defineConfig(kutupApp({ app: 'drive', wasm: ['crypto', 'chat'] }))
